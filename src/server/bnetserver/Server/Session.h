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

#ifndef Session_h__
#define Session_h__

#include "SslContext.h"
#include "SslSocket.h"
#include "Socket.h"
#include "BigNumber.h"
#include "Callback.h"
#include "AccountService.h"
#include "AuthenticationService.h"
#include "ConnectionService.h"
#include "GameUtilitiesService.h"
#include <memory>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

struct Realm;
using boost::asio::ip::tcp;

namespace pb = google::protobuf;

namespace Battlenet
{
    class Session : public Socket<Session, SslSocket<SslContext>>, public pb::RpcChannel
    {
        typedef Socket<Session, SslSocket<SslContext>> BattlenetSocket;

    public:
        struct GameAccountInfo
        {
            void LoadResult(Field* fields);

            uint32 Id;
            std::string Name;
            std::string DisplayName;
            bool IsBanned;
            bool IsPermanenetlyBanned;
            AccountTypes SecurityLevel;
        };

        struct AccountInfo
        {
            void LoadResult(PreparedQueryResult result);

            uint32 Id;
            std::string Login;
            bool IsLockedToIP;
            std::string LockCountry;
            std::string LastIP;
            uint32 FailedLogins;
            bool IsBanned;
            bool IsPermanenetlyBanned;

            std::unordered_map<uint32, GameAccountInfo> GameAccounts;
        };

        explicit Session(tcp::socket&& socket);
        ~Session();

        void Start() override;
        bool Update() override;

        uint32 GetAccountId() const { return _accountInfo->Id; }
        uint32 GetGameAccountId() const { return _gameAccountInfo->Id; }

        bool IsToonOnline() const { return _toonOnline; }
        void SetToonOnline(bool online) { _toonOnline = online; }

        bool IsSubscribedToRealmListUpdates() const { return _subscribedToRealmListUpdates; }

        void AsyncWrite(MessageBuffer* packet);
        void SendResponse(uint32 token, pb::Message* response);
        void CallMethod(pb::MethodDescriptor const* method, pb::RpcController* controller, pb::Message const* request, pb::Message* response, pb::Closure* done) override;

        void HandleLogon(authentication::LogonRequest const* logonRequest);
        void HandleVerifyWebCredentials(authentication::VerifyWebCredentialsRequest const* verifyWebCredentialsRequest);
        void HandleGetGameAccountState(account::GetGameAccountStateRequest const* request, account::GetGameAccountStateResponse* response);
        void HandleProcessClientRequest(game_utilities::ClientRequest const* request, game_utilities::ClientResponse* response);
        void HandleGetAllValuesForAttribute(game_utilities::GetAllValuesForAttributeRequest const* request, game_utilities::GetAllValuesForAttributeResponse* response);

        std::string GetClientInfo() const;

    protected:
        void HandshakeHandler(boost::system::error_code const& error);
        void ReadHandler() override;
        bool ReadHeaderLengthHandler();
        bool ReadHeaderHandler();
        bool ReadDataHandler();

    private:
        void AsyncHandshake();

        void CheckIpCallback(PreparedQueryResult result);

        typedef void(Session::*ClientRequestHandler)(std::unordered_map<std::string, Battlenet::Variant const*> const&, Battlenet::game_utilities::ClientResponse*);
        static std::unordered_map<std::string, ClientRequestHandler> const ClientRequestHandlers;

        void GetRealmListTicket(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response);
        void GetLastCharPlayed(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response);
        void GetRealmList(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response);
        void JoinRealm(std::unordered_map<std::string, Variant const*> const& params, game_utilities::ClientResponse* response);

        MessageBuffer _headerLengthBuffer;
        MessageBuffer _headerBuffer;
        MessageBuffer _packetBuffer;

        std::unique_ptr<AccountInfo> _accountInfo;
        GameAccountInfo* _gameAccountInfo;          // Points at selected game account (inside _gameAccounts)

        std::string _locale;
        std::string _os;
        uint32 _build;

        std::string _ipCountry;

        BigNumber K;    // session key
        std::array<uint8, 32> _clientSecret;

        bool _authed;
        bool _subscribedToRealmListUpdates;
        bool _toonOnline;

        PreparedQueryResultFuture _queryFuture;
        std::function<void(PreparedQueryResult)> _queryCallback;

        Service::Account _accountService;
        Service::Authentication _authenticationService;
        Service::Connection _connectionService;
        Service::GameUtilities _gameUtilitiesService;

        std::unordered_map<uint32, std::unique_ptr<RpcCallback>> _responseCallbacks;
        uint32 _requestToken;
    };
}

#endif // Session_h__
