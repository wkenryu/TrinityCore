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

#ifndef AuthenticationService_h__
#define AuthenticationService_h__

#include "Common.h"
#include "authentication_service.pb.h"

namespace pb = google::protobuf;

namespace Battlenet
{
    class Session;

    namespace Service
    {
        class Authentication : public authentication::AuthenticationService
        {
        public:
            Authentication(Session* session);

            uint32 HandleLogon(authentication::LogonRequest const* request, NoData* respons) override;
            uint32 HandleVerifyWebCredentials(authentication::VerifyWebCredentialsRequest const* request, NoData* respons) override;

        };
    }
}

#endif // AuthenticationService_h__
