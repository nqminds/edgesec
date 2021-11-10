# This file is part of mDNS Reflector (mdns-reflector), a lightweight and performant multicast DNS (mDNS) reflector.
# Copyright (C) 2021 Yuxiang Zhu <me@yux.im>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(mcast mcast.c)
target_link_libraries(mcast PRIVATE os)

add_library(reflection_list reflection_list.c)
target_link_libraries(reflection_list PRIVATE os log)

add_library(reflector reflector.c)
target_link_libraries(reflector PRIVATE mcast mdns_decoder domain eloop if os log)

add_executable(mdns-reflector mdns-reflector.c)
target_link_libraries(mdns-reflector PRIVATE mcast reflection_list reflector eloop os log)
