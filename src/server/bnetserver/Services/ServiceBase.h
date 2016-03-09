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

#ifndef ServiceBase_h__
#define ServiceBase_h__

#include "MessageBuffer.h"
#include "MethodRegistry.h"
#include "Common.h"
#include "rpc_types.pb.h"
#include <google/protobuf/message.h>
#include <google/protobuf/service.h>

namespace Battlenet
{
    class Session;

    class DefaultRpcErrorCollector : public google::protobuf::RpcController
    {
    public:
        bool Failed() const override { return !_error.empty(); }
        void SetFailed(const std::string& reason) override { _error = reason; }
        std::string ErrorText() const override { return _error; }
        void Reset() override { }
        void StartCancel() override { }
        bool IsCanceled() const override { return false; }
        void NotifyOnCancel(google::protobuf::Closure* /*callback*/) override { }

    private:
        std::string _error;
    };

    class NoopCallback : public google::protobuf::Closure
    {
    public:
        void Run() override { }
    };

    template <class ServiceType>
    class ServiceBase : public ServiceType
    {
    public:
        ServiceBase(Session* session) : _session(session) { }

        void HandleMessage(uint32 methodId, uint32 token, MessageBuffer packetData)
        {
            pb::MethodDescriptor const* methodDescriptor = _methodRegistry.GetMethodById(methodId);
            if (!methodDescriptor)
            {
                TC_LOG_ERROR("session.rpc", "%s Client failed to call method: Service %s does not have a method with id %u.",
                    _session->GetClientInfo().c_str(), ServiceType::descriptor()->name().c_str(), methodId);
                return;
            }

            pb::Message* request = GetRequestPrototype(methodDescriptor).New();
            pb::Message* response = nullptr;
            if (methodDescriptor->output_type() != NO_RESPONSE::default_instance().GetDescriptor())
                response = GetResponsePrototype(methodDescriptor).New();

            request->ParseFromArray(packetData.GetReadPointer(), packetData.GetActiveSize());

            TC_LOG_INFO("session.rpc", "%s Client called server method %s with %s { %s }",
                _session->GetClientInfo().c_str(), methodDescriptor->full_name().c_str(),
                request->GetTypeName().c_str(), request->ShortDebugString().c_str());

            DefaultRpcErrorCollector methodCall;
            NoopCallback cb;
            CallMethod(methodDescriptor, &methodCall, request, response, &cb);

            if (!methodCall.Failed())
            {
                if (methodDescriptor->output_type() != NO_RESPONSE::default_instance().GetDescriptor())
                {
                    TC_LOG_INFO("session.rpc", "%s Client called server method %s returned %s { %s }",
                        _session->GetClientInfo().c_str(), methodDescriptor->full_name().c_str(),
                        response->GetTypeName().c_str(), response->ShortDebugString().c_str());

                    _session->SendResponse(token, response);
                }
            }
            else
                TC_LOG_ERROR("session.rpc", "%s Client failed to call method %s with %s { %s }: %s", _session->GetClientInfo().c_str(),
                    methodDescriptor->full_name().c_str(), request->GetTypeName().c_str(),
                    request->ShortDebugString().c_str(), methodCall.ErrorText().c_str());

            delete request;
            delete response;
        }

    protected:
        Session* const _session;
        MethodRegistry<ServiceType> _methodRegistry;
    };

    class RpcCallback : public pb::Closure
    {
    public:
        virtual void Invoke(MessageBuffer packetData) = 0;
        void Run() override final { ASSERT(false, "Do not call stupid API."); }
    };

    template <class CallbackType, void(Session::*Handler)(CallbackType const*)>
    class RpcCallbackImpl final : public RpcCallback
    {
    public:
        RpcCallbackImpl(Session* session) : _session(session) { }

        void Invoke(MessageBuffer packetData) override
        {
            CallbackType message;
            if (message.ParseFromArray(packetData.GetReadPointer(), packetData.GetActiveSize()))
                _session->*Handler(&message);
        }

    private:
        Session* const _session;
    };

    inline uint32 HashServiceName(std::string const& name)
    {
        uint32 hash = 0x811C9DC5;
        for (std::size_t i = 0; i < name.length(); ++i)
        {
            hash ^= name[i];
            hash *= 0x1000193;
        }

        return hash;
    }
}

#endif // ServiceBase_h__
