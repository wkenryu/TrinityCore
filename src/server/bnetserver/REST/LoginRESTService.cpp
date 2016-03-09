/*
 * Copyright (C) 2008-2016 TrinityCore <http://www.trinitycore.org/>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "LoginRESTService.h"
#include "DatabaseEnv.h"
#include "Log.h"
#include "ProtobufJSON.h"
#include "SessionManager.h"
#include "SHA1.h"
#include "SHA256.h"
#include "SslContext.h"
#include "Util.h"
#include "httpget.h"
#include "httppost.h"
#include "soapH.h"
#include "soapStub.h"

extern "C" SOAP_FMAC5 int32 SOAP_FMAC6 soap_serve(soap *soapClient)
{
    unsigned int k = soapClient->max_keep_alive;
    do
    {
        if (soapClient->max_keep_alive > 0 && !--k)
            soapClient->keep_alive = 0;

        if (soap_begin_serve(soapClient))
        {
            if (soapClient->error >= SOAP_STOP)
                continue;
            return soapClient->error;
        }

        return soap_send_fault(soapClient);

    } while (soapClient->keep_alive);

    return SOAP_OK;
}

int32 handle_get_plugin(soap* soapClient)
{
    return sLoginService.HandleGet(soapClient);
}

int32 handle_post_plugin(soap* soapClient)
{
    return sLoginService.HandlePost(soapClient);
}

bool LoginRESTService::Start(boost::asio::io_service& ioService)
{
    _bindIP = sConfigMgr->GetStringDefault("BindIP", "0.0.0.0");
    _port = sConfigMgr->GetIntDefault("LoginREST.Port", 8081);
    if (_port < 0 || _port > 0xFFFF)
    {
        TC_LOG_ERROR("server.rest", "Specified login service port (%d) out of allowed range (1-65535), defaulting to 8081", _port);
        _port = 8081;
    }

    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver resolver(ioService);
    boost::asio::ip::tcp::resolver::iterator end;

    boost::asio::ip::tcp::resolver::query externalAddressQuery(boost::asio::ip::tcp::v4(), sConfigMgr->GetStringDefault("LoginREST.ExternalAddress", ""), std::to_string(_port));
    boost::asio::ip::tcp::resolver::iterator endPoint = resolver.resolve(externalAddressQuery, ec);
    if (endPoint == end || ec)
    {
        TC_LOG_ERROR("server.rest", "Could not resolve LoginREST.ExternalAddress %s", sConfigMgr->GetStringDefault("LoginREST.ExternalAddress", "").c_str());
        return false;
    }

    _externalAddress = endPoint->endpoint();

    boost::asio::ip::tcp::resolver::query localAddressQuery(boost::asio::ip::tcp::v4(), sConfigMgr->GetStringDefault("LoginREST.LocalAddress", ""), std::to_string(_port));
    endPoint = resolver.resolve(localAddressQuery, ec);
    if (endPoint == end || ec)
    {
        TC_LOG_ERROR("server.rest", "Could not resolve LoginREST.ExternalAddress %s", sConfigMgr->GetStringDefault("LoginREST.LocalAddress", "").c_str());
        return false;
    }

    _localAddress = endPoint->endpoint();

    // set up form inputs
    Battlenet::JSON::FormInput* input;
    _formInputs.set_type(Battlenet::JSON::LOGIN_FORM);
    input = _formInputs.add_inputs();
    input->set_input_id("account_name");
    input->set_type("text");
    input->set_label("E-mail");
    input->set_max_length(320);

    input = _formInputs.add_inputs();
    input->set_input_id("password");
    input->set_type("password");
    input->set_label("Password");
    input->set_max_length(16);

    input = _formInputs.add_inputs();
    input->set_input_id("log_in_submit");
    input->set_type("submit");
    input->set_label("Log In");

    _thread = std::thread(std::bind(&LoginRESTService::Run, this));
    return true;
}

void LoginRESTService::Stop()
{
    _stopped = true;
    _thread.join();
}

boost::asio::ip::tcp::endpoint const& LoginRESTService::GetAddressForClient(boost::asio::ip::address const& address) const
{
    if (address.is_loopback())
        return _localAddress;

    if (boost::asio::ip::address_v4::netmask(_localAddress.address().to_v4()).to_ulong() & address.to_v4().to_ulong())
        return _localAddress;

    return _externalAddress;
}

void LoginRESTService::Run()
{
    soap soapServer(SOAP_C_UTFSTRING, SOAP_C_UTFSTRING);

    // check every 3 seconds if world ended
    soapServer.accept_timeout = 3;
    soapServer.recv_timeout = 5;
    soapServer.send_timeout = 5;
    if (!soap_valid_socket(soap_bind(&soapServer, _bindIP.c_str(), _port, 100)))
    {
        TC_LOG_ERROR("server.rest", "Couldn't bind to %s:%d", _bindIP.c_str(), _port);
        return;
    }

    TC_LOG_INFO("server.rest", "Login service bound to http://%s:%d", _bindIP.c_str(), _port);

    http_post_handlers handlers[] =
    {
        { "application/json;charset=utf-8", handle_post_plugin },
        { "application/json", handle_post_plugin },
        { NULL }
    };

    soap_register_plugin_arg(&soapServer, http_get, handle_get_plugin);
    soap_register_plugin_arg(&soapServer, http_post, handlers);
    soap_register_plugin_arg(&soapServer, &ContentTypePlugin::Init, "application/json;charset=utf-8");

    soapServer.ctx = Battlenet::SslContext::instance().native_handle();
    soapServer.ssl_flags = SOAP_SSL_RSA;

    while (!_stopped)
    {
        if (!soap_valid_socket(soap_accept(&soapServer)))
            continue;   // ran into an accept timeout

        std::unique_ptr<soap> soapClient = Trinity::make_unique<soap>(soapServer);
        boost::asio::ip::address_v4 address(soapClient->ip);
        if (soap_ssl_accept(soapClient.get()) != SOAP_OK)
        {
            TC_LOG_DEBUG("server.rest", "Failed SSL handshake from IP=%s", address.to_string().c_str());
            continue;
        }

        TC_LOG_DEBUG("server.rest", "Accepted connection from IP=%s", address.to_string().c_str());

        std::thread([soapClient{ std::move(soapClient) }]
        {
            soap_serve(soapClient.get());
        }).detach();
    }

    soapServer.ctx = nullptr;

    TC_LOG_INFO("server.rest", "Login service exiting...");
}

int32 LoginRESTService::HandleGet(soap* soapClient)
{
    boost::asio::ip::address_v4 address(soapClient->ip);
    std::string ip_address = address.to_string();

    TC_LOG_DEBUG("server.rest", "[%s:%d] Handling GET request path=\"%s\"", soapClient->path);

    static std::string const expectedPath = "/bnetserver/login/";
    if (strstr(soapClient->path, expectedPath.c_str()) != &soapClient->path[0])
        return 404;

    return SendResponse(soapClient, _formInputs);
}

int32 LoginRESTService::HandlePost(soap* soapClient)
{
    boost::asio::ip::address_v4 address(soapClient->ip);
    std::string ip_address = address.to_string();

    TC_LOG_DEBUG("server.rest", "[%s:%d] Handling POST request path=\"%s\"", ip_address.c_str(), soapClient->port, soapClient->path);

    static std::string const expectedPath = "/bnetserver/login/";
    if (strstr(soapClient->path, expectedPath.c_str()) != &soapClient->path[0])
        return 404;

    if (soap_register_plugin_arg(soapClient, &ResponseCodePlugin::Init, nullptr) != SOAP_OK)
        return 500;

    ResponseCodePlugin* responseCode = reinterpret_cast<ResponseCodePlugin*>(soap_lookup_plugin(soapClient, ResponseCodePlugin::PluginId));
    ASSERT(responseCode);

    Battlenet::JSON::LoginResult loginResult;
    responseCode->ErrorCode = 400;

    std::string ipCountry;

    PreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_IP_INFO);
    stmt->setString(0, ip_address);
    stmt->setUInt32(1, address.to_ulong());
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        bool banned = false;
        do
        {
            Field* fields = result->Fetch();
            if (fields[0].GetUInt64() != 0)
                banned = true;

            if (!fields[1].GetString().empty())
                ipCountry = fields[1].GetString();

        } while (result->NextRow());

        if (banned)
        {
            TC_LOG_DEBUG("session", "%s tries to log in using banned IP!", ip_address.c_str());
            loginResult.set_error_code("ACCOUNT_BANNED");
            loginResult.set_error_message("Your account has been banned.");
            return SendResponse(soapClient, loginResult);
        }
    }


    char *buf;
    size_t len;
    soap_http_body(soapClient, &buf, &len);

    Battlenet::JSON::LoginForm loginForm;
    loginResult.set_authentication_state(Battlenet::JSON::LOGIN);
    if (!Battlenet::JSON::Deserialize(buf, &loginForm))
    {
        loginResult.set_error_code("UNABLE_TO_DECODE");
        loginResult.set_error_message("There was an internal error while connecting to Battle.net. Please try again later.");
        return SendResponse(soapClient, loginResult);
    }

    if (loginForm.program_id() != "WoW")
    {
        loginResult.set_error_code("INVALID_PROGRAM");
        loginResult.set_error_message("You have attempted to log into Battle.net with a program not permitted to connect to the service.");
        return SendResponse(soapClient, loginResult);
    }

    if (loginForm.platform_id() != "Win" && loginForm.platform_id() != "Wn64" && loginForm.platform_id() != "Mc64")
    {
        loginResult.set_error_code("INVALID_PLATFORM");
        loginResult.set_error_message("You have attempted to log into Battle.net from an unsupported operating system.");
        return SendResponse(soapClient, loginResult);
    }

    std::string login;
    std::string password;

    for (int32 i = 0; i < loginForm.inputs_size(); ++i)
    {
        if (loginForm.inputs(i).input_id() == "account_name")
            login = loginForm.inputs(i).value();
        else if (loginForm.inputs(i).input_id() == "password")
            password = loginForm.inputs(i).value();
    }

    Utf8ToUpperOnlyLatin(login);
    Utf8ToUpperOnlyLatin(password);

    stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_ACCOUNT_INFO);
    stmt->setString(0, login);
    stmt->setString(1, CalculateShaPassHash(login, std::move(password)));
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (!result)
    {
        loginResult.set_error_code("UNKNOWN_ACCOUNT");
        loginResult.set_error_message("Your login information was incorrect. Please try again.");
        return SendResponse(soapClient, loginResult);
    }

    std::unique_ptr<Battlenet::Session::AccountInfo> accountInfo = Trinity::make_unique<Battlenet::Session::AccountInfo>();
    accountInfo->LoadResult(result);

    // If the IP is 'locked', check that the player comes indeed from the correct IP address
    if (accountInfo->IsLockedToIP)
    {
        TC_LOG_DEBUG("server.rest", "[Battlenet::LogonRequest] Account '%s' is locked to IP - '%s' is logging in from '%s'", accountInfo->Login.c_str(), accountInfo->LastIP.c_str(), ip_address.c_str());

        if (accountInfo->LastIP != ip_address)
        {
            loginResult.set_error_code("ACCOUNT_LOCKED");
            loginResult.set_error_message("Our login system has detected a change in your access pattern.");
            return SendResponse(soapClient, loginResult);
        }
    }
    else
    {
        TC_LOG_DEBUG("server.rest", "[Battlenet::LogonRequest] Account '%s' is not locked to ip", accountInfo->Login.c_str());
        if (accountInfo->LockCountry.empty() || accountInfo->LockCountry == "00")
            TC_LOG_DEBUG("server.rest", "[Battlenet::LogonRequest] Account '%s' is not locked to country", accountInfo->Login.c_str());
        else if (!accountInfo->LockCountry.empty() && !ipCountry.empty())
        {
            TC_LOG_DEBUG("server.rest", "[Battlenet::LogonRequest] Account '%s' is locked to country: '%s' Player country is '%s'", accountInfo->Login.c_str(), accountInfo->LockCountry.c_str(), ipCountry.c_str());
            if (ipCountry != accountInfo->LockCountry)
            {
                loginResult.set_error_code("ACCOUNT_LOCKED");
                loginResult.set_error_message("Our login system has detected a change in your access pattern.");
                return SendResponse(soapClient, loginResult);
            }
        }
    }

    // If the account is banned, reject the logon attempt
    if (accountInfo->IsBanned)
    {
        if (accountInfo->IsPermanenetlyBanned)
        {
            TC_LOG_DEBUG("server.rest", "'%s:%d' [Battlenet::LogonRequest] Banned account %s tried to login!", ip_address.c_str(), soapClient->port, accountInfo->Login.c_str());
            loginResult.set_error_code("ACCOUNT_BANNED");
            loginResult.set_error_message("Your account has been banned.");
            return SendResponse(soapClient, loginResult);
        }
        else
        {
            TC_LOG_DEBUG("server.rest", "'%s:%d' [Battlenet::LogonRequest] Temporarily banned account %s tried to login!", ip_address.c_str(), soapClient->port, accountInfo->Login.c_str());
            loginResult.set_error_code("ACCOUNT_SUSPENDED");
            loginResult.set_error_message("Your account has been suspended.");
            return SendResponse(soapClient, loginResult);
        }
    }

    responseCode->ErrorCode = 0;

    BigNumber ticket;
    ticket.SetRand(20 * 8);

    std::string loginTicket = ("TC-" + ByteArrayToHexStr(ticket.AsByteArray(20).get(), 20)).c_str();

    loginResult.set_authentication_state(Battlenet::JSON::DONE);
    loginResult.set_login_ticket(loginTicket);

    sSessionMgr.AddLoginTicket(loginTicket, std::move(accountInfo));

    return SendResponse(soapClient, loginResult);
}

int32 LoginRESTService::SendResponse(soap* soapClient, google::protobuf::Message const& response)
{
    std::string jsonResponse = Battlenet::JSON::Serialize(response);

    soap_response(soapClient, SOAP_FILE);
    soap_send_raw(soapClient, jsonResponse.c_str(), jsonResponse.length());
    return soap_end_send(soapClient);
}

std::string LoginRESTService::CalculateShaPassHash(std::string const& name, std::string const& password)
{
    SHA256Hash email;
    email.UpdateData(name);
    email.Finalize();

    SHA256Hash sha;
    sha.UpdateData(ByteArrayToHexStr(email.GetDigest(), email.GetLength()));
    sha.UpdateData(":");
    sha.UpdateData(password);
    sha.Finalize();

    return ByteArrayToHexStr(sha.GetDigest(), sha.GetLength(), true);
}

Namespace namespaces[] =
{
    { NULL, NULL, NULL, NULL }
};

LoginRESTService& LoginRESTService::Instance()
{
    static LoginRESTService instance;
    return instance;
}

char const* const LoginRESTService::ResponseCodePlugin::PluginId = "bnet-error-code";

int32 LoginRESTService::ResponseCodePlugin::Init(soap* s, soap_plugin* p, void* /*arg*/)
{
    ResponseCodePlugin* data = new ResponseCodePlugin();
    data->fresponse = s->fresponse;

    p->id = PluginId;
    p->fdelete = &Destroy;
    p->data = data;

    s->fresponse = &ChangeResponse;
    return SOAP_OK;
}

void LoginRESTService::ResponseCodePlugin::Destroy(soap* s, soap_plugin* p)
{
    ResponseCodePlugin* data = reinterpret_cast<ResponseCodePlugin*>(p->data);
    s->fresponse = data->fresponse;
    delete data;
}

int32 LoginRESTService::ResponseCodePlugin::ChangeResponse(soap* s, int32 originalResponse, size_t contentLength)
{
    ResponseCodePlugin* self = reinterpret_cast<ResponseCodePlugin*>(soap_lookup_plugin(s, PluginId));
    return self->fresponse(s, self->ErrorCode && originalResponse == SOAP_FILE ? self->ErrorCode : originalResponse, contentLength);
}

char const* const LoginRESTService::ContentTypePlugin::PluginId = "bnet-content-type";

int32 LoginRESTService::ContentTypePlugin::Init(soap* s, soap_plugin* p, void* arg)
{
    ContentTypePlugin* data = new ContentTypePlugin();
    data->fposthdr = s->fposthdr;
    data->ContentType = reinterpret_cast<char const*>(arg);

    p->id = PluginId;
    p->fdelete = &Destroy;
    p->data = data;

    s->fposthdr = &OnSetHeader;
    return SOAP_OK;
}

void LoginRESTService::ContentTypePlugin::Destroy(soap* s, soap_plugin* p)
{
    ContentTypePlugin* data = reinterpret_cast<ContentTypePlugin*>(p->data);
    s->fposthdr = data->fposthdr;
    delete data;
}

int32 LoginRESTService::ContentTypePlugin::OnSetHeader(soap* s, char const* key, char const* value)
{
    ContentTypePlugin* self = reinterpret_cast<ContentTypePlugin*>(soap_lookup_plugin(s, PluginId));
    if (key && !strcmp("Content-Type", key))
        value = self->ContentType;

    return self->fposthdr(s, key, value);
}
