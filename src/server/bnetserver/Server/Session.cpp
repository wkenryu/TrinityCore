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

#include "SessionManager.h"
#include "ByteConverter.h"
#include "Database/DatabaseEnv.h"
#include "Log.h"
#include "LoginRESTService.h"
#include "ProtobufJSON.h"
#include "RealmList.h"
#include "SHA256.h"
#include "challenge_service.pb.h"
#include "JSONStructures.pb.h"
#include "rpc_types.pb.h"
#include <zlib.h>

void Battlenet::Session::AccountInfo::LoadResult(PreparedQueryResult result)
{
    // ba.id, ba.email, ba.locked, ba.lock_country, ba.last_ip, ba.failed_logins, bab.unbandate > UNIX_TIMESTAMP() OR bab.unbandate = bab.bandate, bab.unbandate = bab.bandate FROM battlenet_accounts ba LEFT JOIN battlenet_account_bans bab WHERE email = ?
    Field* fields = result->Fetch();
    Id = fields[0].GetUInt32();
    Login = fields[1].GetString();
    IsLockedToIP = fields[2].GetBool();
    LockCountry = fields[3].GetString();
    LastIP = fields[4].GetString();
    FailedLogins = fields[5].GetUInt32();
    IsBanned = fields[6].GetUInt64() != 0;
    IsPermanenetlyBanned = fields[7].GetUInt64() != 0;

    static uint32 const GameAccountFieldsOffset = 11;

    do
    {
        GameAccounts[result->Fetch()[GameAccountFieldsOffset].GetUInt32()].LoadResult(result->Fetch() + GameAccountFieldsOffset);

    } while (result->NextRow());
}

void Battlenet::Session::GameAccountInfo::LoadResult(Field* fields)
{
    // a.id, a.username, ab.unbandate > UNIX_TIMESTAMP() OR ab.unbandate = ab.bandate, ab.unbandate = ab.bandate, aa.gmlevel
    Id = fields[0].GetUInt32();
    Name = fields[1].GetString();
    IsBanned = fields[2].GetUInt64() != 0;
    IsPermanenetlyBanned = fields[3].GetUInt64() != 0;
    SecurityLevel = AccountTypes(fields[4].GetUInt8());

    std::size_t hashPos = Name.find('#');
    if (hashPos != std::string::npos)
        DisplayName = std::string("WoW") + Name.substr(hashPos + 1);
    else
        DisplayName = Name;
}

Battlenet::Session::Session(tcp::socket&& socket) : BattlenetSocket(std::move(socket)), _accountInfo(new AccountInfo()), _gameAccountInfo(nullptr), _locale(),
    _os(), _build(0), _ipCountry(), K(), _authed(false), _subscribedToRealmListUpdates(false), _toonOnline(false),
    _accountService(this), _authenticationService(this), _connectionService(this), _gameUtilitiesService(this), _requestToken(0)
{
    _headerLengthBuffer.Resize(2);
}

Battlenet::Session::~Session()
{
    if (_authed)
        sSessionMgr.RemoveSession(this);
}

void Battlenet::Session::AsyncHandshake()
{
    underlying_stream().async_handshake(ssl::stream_base::server, std::bind(&Session::HandshakeHandler, shared_from_this(), std::placeholders::_1));
}

void Battlenet::Session::Start()
{
    std::string ip_address = GetRemoteIpAddress().to_string();
    TC_LOG_TRACE("session", "%s Accepted connection", GetClientInfo().c_str());

    // Verify that this IP is not in the ip_banned table
    LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_DEL_EXPIRED_IP_BANS));

    PreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_IP_INFO);
    stmt->setString(0, ip_address);
    stmt->setUInt32(1, inet_addr(ip_address.c_str()));

    _queryCallback = std::bind(&Battlenet::Session::CheckIpCallback, this, std::placeholders::_1);
    _queryFuture = LoginDatabase.AsyncQuery(stmt);
}

void Battlenet::Session::CheckIpCallback(PreparedQueryResult result)
{
    if (result)
    {
        bool banned = false;
        do
        {
            Field* fields = result->Fetch();
            if (fields[0].GetUInt64() != 0)
                banned = true;

            if (!fields[1].GetString().empty())
                _ipCountry = fields[1].GetString();

        } while (result->NextRow());

        if (banned)
        {
            TC_LOG_DEBUG("session", "%s tries to log in using banned IP!", GetClientInfo().c_str());
            CloseSocket();
            return;
        }
    }

    AsyncHandshake();
}

bool Battlenet::Session::Update()
{
    if (!BattlenetSocket::Update())
        return false;

    if (_queryFuture.valid() && _queryFuture.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
    {
        auto callback = std::move(_queryCallback);
        _queryCallback = nullptr;
        callback(_queryFuture.get());
    }

    return true;
}

void Battlenet::Session::AsyncWrite(MessageBuffer* packet)
{
    if (!IsOpen())
        return;

    QueuePacket(std::move(*packet));
}

void Battlenet::Session::SendResponse(uint32 token, pb::Message* response)
{
    Header header;
    header.set_is_response(true);
    header.set_token(token);
    header.set_service_id(0xFE);
    header.set_size(response->ByteSize());

    uint16 headerSize = header.ByteSize();
    EndianConvertReverse(headerSize);

    MessageBuffer packet;
    packet.Write(&headerSize, sizeof(headerSize));
    uint8* ptr = packet.GetWritePointer();
    packet.WriteCompleted(header.ByteSize());
    header.SerializeToArray(ptr, header.ByteSize());
    ptr = packet.GetWritePointer();
    packet.WriteCompleted(response->ByteSize());
    response->SerializeToArray(ptr, response->ByteSize());

    AsyncWrite(&packet);
}

void Battlenet::Session::CallMethod(pb::MethodDescriptor const* method, pb::RpcController* /*controller*/, pb::Message const* request, pb::Message* /*response*/, pb::Closure* done)
{
    TC_LOG_INFO("session.rpc", "%s Server called client method %s with %s { %s }", GetClientInfo().c_str(),
        method->full_name().c_str(), request->GetTypeName().c_str(), request->ShortDebugString().c_str());

    Header header;
    header.set_service_id(0);
    header.set_service_hash(HashServiceName(method->service()->options().GetExtension(original_fully_qualified_descriptor_name)));
    header.set_method_id(method->options().GetExtension(method_id));
    header.set_size(request->ByteSize());
    header.set_token(_requestToken++);

    uint16 headerSize = header.ByteSize();
    EndianConvertReverse(headerSize);

    MessageBuffer packet;
    packet.Write(&headerSize, sizeof(headerSize));
    uint8* ptr = packet.GetWritePointer();
    packet.WriteCompleted(header.ByteSize());
    header.SerializeToArray(ptr, header.ByteSize());
    ptr = packet.GetWritePointer();
    packet.WriteCompleted(request->ByteSize());
    request->SerializeToArray(ptr, request->ByteSize());

    if (done)
        _responseCallbacks[header.token()].reset(static_cast<RpcCallback*>(done));

    AsyncWrite(&packet);
}

void Battlenet::Session::HandleLogon(authentication::LogonRequest const* logonRequest)
{
    _locale = logonRequest->locale();
    _os = logonRequest->platform();

    ip::tcp::endpoint const& endpoint = sLoginService.GetAddressForClient(GetRemoteIpAddress());

    challenge::ChallengeExternalRequest externalChallenge;
    externalChallenge.set_payload_type("web_auth_url");
    externalChallenge.set_payload(Trinity::StringFormat("https://%s:%u/bnetserver/login/", endpoint.address().to_string().c_str(), endpoint.port()));
    challenge::ChallengeListener_Stub(this).OnExternalChallenge(nullptr, &externalChallenge, nullptr, nullptr);
}

void Battlenet::Session::HandleVerifyWebCredentials(authentication::VerifyWebCredentialsRequest const* verifyWebCredentialsRequest)
{
    authentication::LogonResult logonResult;
    logonResult.set_error_code(0);
    _accountInfo = sSessionMgr.VerifyLoginTicket(verifyWebCredentialsRequest->web_credentials());
    if (!_accountInfo)
    {
        authentication::AuthenticationListener_Stub(this).OnLogonComplete(nullptr, &logonResult, nullptr, nullptr);
        return;
    }

    K.SetRand(8 * 64);

    logonResult.mutable_account_id()->set_low(_accountInfo->Id);
    logonResult.mutable_account_id()->set_high(UI64LIT(0x100000000000000));
    for (auto itr = _accountInfo->GameAccounts.begin(); itr != _accountInfo->GameAccounts.end(); ++itr)
    {
        if (!itr->second.IsBanned)
        {
            EntityId* gameAccountId = logonResult.add_game_account_id();
            gameAccountId->set_low(itr->second.Id);
            gameAccountId->set_high(UI64LIT(0x200000200576F57));
        }
    }

    if (!_ipCountry.empty())
        logonResult.set_geoip_country(_ipCountry);

    logonResult.set_session_key(K.AsByteArray(64).get(), 64);

    authentication::AuthenticationListener_Stub(this).OnLogonComplete(nullptr, &logonResult, nullptr, nullptr);
}

void Battlenet::Session::HandleGetGameAccountState(account::GetGameAccountStateRequest const* request, account::GetGameAccountStateResponse* response)
{
    if (request->options().field_game_level_info())
    {
        auto itr = _accountInfo->GameAccounts.find(request->game_account_id().low());
        if (itr != _accountInfo->GameAccounts.end())
        {
            response->mutable_state()->mutable_game_level_info()->set_name(itr->second.DisplayName);
            response->mutable_state()->mutable_game_level_info()->set_program(5730135); // WoW
        }

        response->mutable_tags()->set_game_level_info_tag(0x5C46D483);
    }
}

std::unordered_map<std::string, Battlenet::Session::ClientRequestHandler> const Battlenet::Session::ClientRequestHandlers =
{
    { "Command_RealmListTicketRequest_v1_b9", &Battlenet::Session::GetRealmListTicket },
    //{ "Command_LastCharPlayedRequest_v1_b9", &Battlenet::Session::GetLastCharPlayed },
    { "Command_RealmListRequest_v1_b9", &Battlenet::Session::GetRealmList },
    { "Command_RealmJoinRequest_v1_b9", &Battlenet::Session::JoinRealm },
};

void Battlenet::Session::HandleProcessClientRequest(game_utilities::ClientRequest const* request, game_utilities::ClientResponse* response)
{
    Attribute const* command = nullptr;
    std::unordered_map<std::string, Variant const*> params;

    for (int32 i = 0; i < request->attribute_size(); ++i)
    {
        Attribute const& attr = request->attribute(i);
        params[attr.name()] = &attr.value();
        if (strstr(attr.name().c_str(), "Command_") == attr.name().c_str())
            command = &attr;
    }

    if (!command)
    {
        TC_LOG_ERROR("session.rpc", "%s sent ClientRequest with no command.", GetClientInfo().c_str());
        return;
    }

    auto itr = ClientRequestHandlers.find(command->name());
    if (itr == ClientRequestHandlers.end())
    {
        TC_LOG_ERROR("session.rpc", "%s sent ClientRequest with unknown command %s.", GetClientInfo().c_str(), command->name().c_str());
        return;
    }

    (this->*itr->second)(params, response);
}

inline Battlenet::Variant const* GetParam(std::unordered_map<std::string, Battlenet::Variant const*> const& params, char const* paramName)
{
    auto itr = params.find(paramName);
    return itr != params.end() ? itr->second : nullptr;
}

void Battlenet::Session::GetRealmListTicket(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response)
{
    if (Variant const* identity = GetParam(params, "Param_Identity"))
    {
        JSON::RealmListTicketIdentity data;
        std::size_t jsonStart = identity->blob_value().find(':');
        if (jsonStart != std::string::npos && JSON::Deserialize(identity->blob_value().substr(jsonStart + 1), &data))
        {
            auto itr = _accountInfo->GameAccounts.find(data.gameaccountid());
            if (itr != _accountInfo->GameAccounts.end())
                _gameAccountInfo = &itr->second;
        }
    }

    if (Variant const* clientInfo = GetParam(params, "Param_ClientInfo"))
    {
        JSON::RealmListTicketClientInformation data;
        std::size_t jsonStart = clientInfo->blob_value().find(':');
        if (jsonStart != std::string::npos && JSON::Deserialize(clientInfo->blob_value().substr(jsonStart + 1), &data))
        {
            if (_clientSecret.size() == data.info().secret().size())
            {
                _build = data.info().version().versionbuild();
                memcpy(_clientSecret.data(), data.info().secret().data(), _clientSecret.size());
            }
        }
    }

    if (_gameAccountInfo && _build)
    {
        SQLTransaction trans = LoginDatabase.BeginTransaction();

        PreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_BNET_LAST_LOGIN_INFO);
        stmt->setString(0, GetRemoteIpAddress().to_string());
        stmt->setUInt8(1, GetLocaleByName(_locale));
        stmt->setString(2, _os);
        stmt->setUInt32(3, _accountInfo->Id);
        trans->Append(stmt);

        stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_BNET_SESSION_KEY);
        stmt->setString(0, K.AsHexStr());
        stmt->setBool(1, true);
        stmt->setUInt32(2, _accountInfo->Id);
        trans->Append(stmt);

        LoginDatabase.CommitTransaction(trans);

        _authed = true;
        sSessionMgr.AddSession(this);

        Attribute* attribute = response->add_attribute();
        attribute->set_name("Param_RealmListTicket");
        attribute->mutable_value()->set_blob_value("ListTicket");
    }
}

void Battlenet::Session::GetLastCharPlayed(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response)
{
    // TODO: this is important for rejoining last played realm, realmName cvar was removed
}

void Battlenet::Session::GetRealmList(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response)
{
    if (!_gameAccountInfo)
        return;

    std::string subRegionId;
    if (Variant const* subRegion = GetParam(params, "Command_RealmListRequest_v1_b9"))
        subRegionId = subRegion->string_value();

    JSON::RealmListUpdates realmList;
    for (RealmList::RealmMap::value_type const& i : sRealmList->GetRealms())
    {
        Realm const* realm = &i.second;
        if (realm->Id.GetSubRegionAddress() != subRegionId)
            continue;

        uint32 flag = realm->Flags;
        if (realm->Build != _build)
            flag |= REALM_FLAG_VERSION_MISMATCH;

        JSON::RealmState* state = realmList.add_updates();
        state->mutable_update()->set_wowrealmaddress(realm->Id.GetAddress());
        state->mutable_update()->set_cfgtimezonesid(1);
        state->mutable_update()->set_populationstate((realm->Flags & REALM_FLAG_OFFLINE) ? 0u : std::max(uint32(realm->PopulationLevel), 1u));
        state->mutable_update()->set_cfgcategoriesid(realm->Timezone);

        JSON::ClientVersion* version = state->mutable_update()->mutable_version();
        if (RealmBuildInfo const* buildInfo = sRealmList->GetBuildInfo(realm->Build))
        {
            version->set_versionmajor(buildInfo->MajorVersion);
            version->set_versionminor(buildInfo->MinorVersion);
            version->set_versionrevision(buildInfo->BugfixVersion);
            version->set_versionbuild(buildInfo->Build);
        }
        else
        {
            version->set_versionmajor(6);
            version->set_versionminor(2);
            version->set_versionrevision(4);
            version->set_versionbuild(realm->Build);
        }

        state->mutable_update()->set_cfgrealmsid(realm->Id.Realm);
        state->mutable_update()->set_flags(flag);
        state->mutable_update()->set_name(realm->Name);
        state->mutable_update()->set_cfgconfigsid(realm->GetConfigId());
        state->mutable_update()->set_cfglanguagesid(1);

        state->set_deleting(false);
    }

    std::string json = "JSONRealmListUpdates:" + JSON::Serialize(realmList);

    uLong compressedLength = compressBound(json.length());
    std::vector<uint8> compressed;
    compressed.resize(4 + compressedLength);
    *reinterpret_cast<uint32*>(compressed.data()) = json.length() + 1;

    if (compress(compressed.data() + 4, &compressedLength, reinterpret_cast<uint8 const*>(json.c_str()), json.length() + 1) != Z_OK)
        return;

    Attribute* attribute = response->add_attribute();
    attribute->set_name("Param_RealmList");
    attribute->mutable_value()->set_blob_value(compressed.data(), compressedLength + 4);

    PreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_BNET_CHARACTER_COUNTS);
    stmt->setUInt32(0, _gameAccountInfo->Id);

    JSON::RealmCharacterCountList realmCharacterCounts;
    if (PreparedQueryResult result = LoginDatabase.Query(stmt))
    {
        do
        {
            Field* fields = result->Fetch();
            JSON::RealmCharacterCountEntry* countEntry = realmCharacterCounts.add_counts();
            countEntry->set_wowrealmaddress(RealmHandle(fields[2].GetUInt8(), fields[3].GetUInt8(), fields[1].GetUInt32()).GetAddress());
            countEntry->set_count(fields[0].GetUInt8());
        } while (result->NextRow());
    }

    json = "JSONRealmCharacterCountList:" + JSON::Serialize(realmCharacterCounts);

    compressedLength = compressBound(json.length());
    compressed.resize(4 + compressedLength);
    *reinterpret_cast<uint32*>(compressed.data()) = json.length() + 1;

    if (compress(compressed.data() + 4, &compressedLength, reinterpret_cast<uint8 const*>(json.c_str()), json.length() + 1) != Z_OK)
        return;

    attribute = response->add_attribute();
    attribute->set_name("Param_CharacterCountList");
    attribute->mutable_value()->set_blob_value(compressed.data(), compressedLength + 4);
}

void Battlenet::Session::JoinRealm(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response)
{
    if (Variant const* realmAddress = GetParam(params, "Param_RealmAddress"))
    {
        if (Realm const* realm = sRealmList->GetRealm(RealmHandle(realmAddress->uint_value())))
        {
            if (realm->Flags & (REALM_FLAG_OFFLINE | REALM_FLAG_VERSION_MISMATCH) || realm->Build != _build)
                return;

            JSON::RealmListServerIPAddresses serverAddresses;
            JSON::RealmIPAddressFamily* addressFamily = serverAddresses.add_families();
            addressFamily->set_family(1);
            JSON::IPAddress* address = addressFamily->add_addresses();
            address->set_ip(realm->GetAddressForClient(GetRemoteIpAddress()).address().to_string());
            address->set_port(realm->Port);

            std::string json = "JSONRealmListServerIPAddresses:" + JSON::Serialize(serverAddresses);

            uLong compressedLength = compressBound(json.length());
            std::vector<uint8> compressed;
            compressed.resize(4 + compressedLength);
            *reinterpret_cast<uint32*>(compressed.data()) = json.length() + 1;

            if (compress(compressed.data() + 4, &compressedLength, reinterpret_cast<uint8 const*>(json.c_str()), json.length() + 1) != Z_OK)
                return;

            BigNumber serverSecret;
            serverSecret.SetRand(8 * 32);

            SHA256Hash wowSessionKey;
            wowSessionKey.UpdateData(_clientSecret.data(), _clientSecret.size());
            wowSessionKey.UpdateData(serverSecret.AsByteArray(32).get(), 32);
            wowSessionKey.Finalize();

            LoginDatabase.DirectPExecute("UPDATE account SET sessionkey = '%s', last_ip = '%s', last_login = NOW(), locale = %u, failed_logins = 0, os = '%s' WHERE id = %u",
                ByteArrayToHexStr(wowSessionKey.GetDigest(), wowSessionKey.GetLength(), true).c_str(), GetRemoteIpAddress().to_string().c_str(),
                GetLocaleByName(_locale), _os.c_str(), _gameAccountInfo->Id);

            Attribute* attribute = response->add_attribute();
            attribute->set_name("Param_RealmJoinTicket");
            attribute->mutable_value()->set_blob_value(_gameAccountInfo->Name);

            attribute = response->add_attribute();
            attribute->set_name("Param_ServerAddresses");
            attribute->mutable_value()->set_blob_value(compressed.data(), compressedLength + 4);

            attribute = response->add_attribute();
            attribute->set_name("Param_JoinSecret");
            attribute->mutable_value()->set_blob_value(serverSecret.AsByteArray(32).get(), 32);
        }
    }
}

void Battlenet::Session::HandleGetAllValuesForAttribute(game_utilities::GetAllValuesForAttributeRequest const* request, game_utilities::GetAllValuesForAttributeResponse* response)
{
    if (request->attribute_key() == "Command_RealmListRequest_v1_b9")
        for (std::string const& subRegion : sRealmList->GetSubRegions())
            response->add_attribute_value()->set_string_value(subRegion);
}

void Battlenet::Session::HandshakeHandler(boost::system::error_code const& error)
{
    if (error)
    {
        TC_LOG_ERROR("session", "%s SSL Handshake failed %s", GetClientInfo().c_str(), error.message().c_str());
        CloseSocket();
        return;
    }

    AsyncRead();
}

template<bool(Battlenet::Session::*processMethod)(), MessageBuffer Battlenet::Session::*outputBuffer>
inline bool PartialProcessPacket(Battlenet::Session* session, MessageBuffer& inputBuffer)
{
    MessageBuffer& buffer = session->*outputBuffer;

    // We have full read header, now check the data payload
    if (buffer.GetRemainingSpace() > 0)
    {
        // need more data in the payload
        std::size_t readDataSize = std::min(inputBuffer.GetActiveSize(), buffer.GetRemainingSpace());
        buffer.Write(inputBuffer.GetReadPointer(), readDataSize);
        inputBuffer.ReadCompleted(readDataSize);
    }

    if (buffer.GetRemainingSpace() > 0)
    {
        // Couldn't receive the whole data this time.
        ASSERT(inputBuffer.GetActiveSize() == 0);
        return false;
    }

    // just received fresh new payload
    if (!(session->*processMethod)())
    {
        session->CloseSocket();
        return false;
    }

    return true;
}

void Battlenet::Session::ReadHandler()
{
    if (!IsOpen())
        return;

    MessageBuffer& packet = GetReadBuffer();
    while (packet.GetActiveSize() > 0)
    {
        if (!PartialProcessPacket<&Battlenet::Session::ReadHeaderLengthHandler, &Battlenet::Session::_headerLengthBuffer>(this, packet))
            break;

        if (!PartialProcessPacket<&Battlenet::Session::ReadHeaderHandler, &Battlenet::Session::_headerBuffer>(this, packet))
            break;

        if (!PartialProcessPacket<&Battlenet::Session::ReadDataHandler, &Battlenet::Session::_packetBuffer>(this, packet))
            break;

        _headerLengthBuffer.Reset();
        _headerBuffer.Reset();
    }

    AsyncRead();
}

bool Battlenet::Session::ReadHeaderLengthHandler()
{
    uint16 len = *reinterpret_cast<uint16*>(_headerLengthBuffer.GetReadPointer());
    EndianConvertReverse(len);
    _headerBuffer.Resize(len);
    return true;
}

bool Battlenet::Session::ReadHeaderHandler()
{
    Header header;
    if (!header.ParseFromArray(_headerBuffer.GetReadPointer(), _headerBuffer.GetActiveSize()))
        return true;

    _packetBuffer.Resize(header.size());
    return true;
}

bool Battlenet::Session::ReadDataHandler()
{
    Header header;
    header.ParseFromArray(_headerBuffer.GetReadPointer(), _headerBuffer.GetActiveSize());

    if (header.service_id() != 0xFE)
    {
        switch (header.service_hash())
        {
            case Service::Account::Hash::value:
                _accountService.HandleMessage(header.method_id(), header.token(), std::move(_packetBuffer));
                break;
            case Service::Authentication::Hash::value:
                _authenticationService.HandleMessage(header.method_id(), header.token(), std::move(_packetBuffer));
                break;
            case Service::Connection::Hash::value:
                _connectionService.HandleMessage(header.method_id(), header.token(), std::move(_packetBuffer));
                break;
            case Service::GameUtilities::Hash::value:
                _gameUtilitiesService.HandleMessage(header.method_id(), header.token(), std::move(_packetBuffer));
                break;
            default:
                TC_LOG_INFO("session.rpc", "Unhandled service_hash 0x%X method_id %u", header.service_hash(), header.method_id());
                break;
        }
    }
    else
    {
        auto itr = _responseCallbacks.find(header.token());
        if (itr != _responseCallbacks.end())
        {
            itr->second->Invoke(std::move(_packetBuffer));
            _responseCallbacks.erase(header.token());
        }
        else
            _packetBuffer.Reset();
    }

    return true;
}

std::string Battlenet::Session::GetClientInfo() const
{
    std::ostringstream stream;
    stream << '[' << GetRemoteIpAddress() << ':' << GetRemotePort();
    if (_accountInfo && !_accountInfo->Login.empty())
        stream << ", Account: " << _accountInfo->Login;

    if (_gameAccountInfo)
        stream << ", Game account: " << _gameAccountInfo->Name;

    stream << ']';

    return stream.str();
}
