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

#ifndef ConnectionService_h__
#define ConnectionService_h__

#include "Common.h"
#include "ServiceBase.h"
#include "connection_service.pb.h"

namespace pb = google::protobuf;

namespace Battlenet
{
    class Session;

    namespace Service
    {
        class Connection : public ServiceBase<connection::ConnectionService>
        {
            typedef ServiceBase<connection::ConnectionService> ConnectionServiceBase;

        public:
            typedef std::integral_constant<uint32, 0x65446991> Hash;

            Connection(Session* session);

            void Connect(pb::RpcController* controller, connection::ConnectRequest const* request, connection::ConnectResponse* response, pb::Closure* done) override;
            void KeepAlive(pb::RpcController* /*controller*/, NoData const* /*request*/, NO_RESPONSE* /*response*/, pb::Closure* /*done*/) override { }
            void RequestDisconnect(pb::RpcController* controller, connection::DisconnectRequest const* request, NO_RESPONSE* response, pb::Closure* done) override;
        };
    }
}

#endif // ConnectionService_h__
