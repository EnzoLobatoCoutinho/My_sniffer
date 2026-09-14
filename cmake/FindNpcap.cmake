include(FindPackageHandleStandardArgs)

set(NPCAP_SDK_DIR "" CACHE PATH "Racine du SDK de developpement Npcap")

if(NOT NPCAP_SDK_DIR AND DEFINED ENV{NPCAP_SDK_DIR})
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
endif()

find_path(NPCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS "${NPCAP_SDK_DIR}"
    PATH_SUFFIXES Include include
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_NPCAP_LIBRARY_SUFFIXES Lib/x64 Lib/win64 Lib)
else()
    set(_NPCAP_LIBRARY_SUFFIXES Lib Lib/x86)
endif()

find_library(NPCAP_WPCAP_LIBRARY
    NAMES wpcap
    HINTS "${NPCAP_SDK_DIR}"
    PATH_SUFFIXES ${_NPCAP_LIBRARY_SUFFIXES}
)

find_library(NPCAP_PACKET_LIBRARY
    NAMES Packet
    HINTS "${NPCAP_SDK_DIR}"
    PATH_SUFFIXES ${_NPCAP_LIBRARY_SUFFIXES}
)

find_package_handle_standard_args(Npcap
    REQUIRED_VARS NPCAP_INCLUDE_DIR NPCAP_WPCAP_LIBRARY NPCAP_PACKET_LIBRARY
)

if(Npcap_FOUND AND NOT TARGET Npcap::Npcap)
    add_library(Npcap::Npcap UNKNOWN IMPORTED)
    set_target_properties(Npcap::Npcap PROPERTIES
        IMPORTED_IMPLIB "${NPCAP_WPCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${NPCAP_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${NPCAP_PACKET_LIBRARY};Ws2_32;Iphlpapi"
    )
endif()

mark_as_advanced(
    NPCAP_INCLUDE_DIR
    NPCAP_WPCAP_LIBRARY
    NPCAP_PACKET_LIBRARY
)