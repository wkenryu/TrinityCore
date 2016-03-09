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

#ifndef MethodRegistry_h__
#define MethodRegistry_h__

#include "Common.h"
#include "method_options.pb.h"
#include <google/protobuf/descriptor.h>

namespace pb = google::protobuf;

template<class ServiceType>
class MethodRegistry
{
public:
    MethodRegistry()
    {
        pb::ServiceDescriptor const* serviceDescriptor = ServiceType::descriptor();
        for (int32 i = 0; i < serviceDescriptor->method_count(); ++i)
        {
            pb::MethodDescriptor const* methodDescriptor = serviceDescriptor->method(i);
            if (uint32 methodId = methodDescriptor->options().GetExtension(Battlenet::method_id))
                _methodsById[methodId] = methodDescriptor;
        }
    }

    pb::MethodDescriptor const* GetMethodById(uint32 methodId) const
    {
        auto itr = _methodsById.find(methodId);
        if (itr != _methodsById.end())
            return itr->second;

        return nullptr;
    }

private:
    std::unordered_map<uint32, pb::MethodDescriptor const*> _methodsById;
};

#endif // MethodRegistry_h__
