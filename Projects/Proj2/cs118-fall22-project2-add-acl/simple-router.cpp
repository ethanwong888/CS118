/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  uint16_t packetType = ethertype(packet.data());
  std::size_t ethernetSize = sizeof(ethernet_hdr);
  std::size_t arpSize = sizeof(arp_hdr);
  std::size_t ipSize = sizeof(ip_hdr);

  // ignore packet if it is not destined to router
  if ((macToString(packet) != macToString(iface->addr)) && (macToString(packet) != "ff:ff:ff:ff:ff:ff") && (macToString(packet) != "FF:FF:FF:FF:FF:FF")) {
    std::cerr << "Packet not destined to router. Ignoring." << std::endl;
    return;
  }
 
  // IPv4 PACKET
  if (packetType == ethertype_ip) {
    Buffer IPPacket(packet);
    ip_hdr* IPHeader = (ip_hdr*) (ethernetSize + IPPacket.data());
    uint16_t checksum = IPHeader->ip_sum;
    IPHeader->ip_sum = 0;

    // if packet is less than minimum size, drop it
    if (packet.size() < (ethernetSize + ipSize)) {
      std::cerr << "IP Packet is too short. Ignoring." << std::endl;
      return;
    }
    
    // stop if checksum is incorrect
    if (cksum(IPHeader, ipSize) != checksum) {
      std::cerr << "Invalid checksum. Ignoring." << std::endl;
      return;
    }
    
    // proceed normally
    else {
      // check TTL
      if (IPHeader->ip_ttl == 0) {
        std::cerr << "TTL (Time to Live) is 0. Goodbye." << std::endl;
        return;
      }

      // decrement TTL
      IPHeader->ip_ttl--;
      if (IPHeader->ip_ttl <= 0) {
        std::cerr << "TTL (Time to Live) is 0. Goodbye." << std::endl;
        return;
      }

      // recompute checksum
      IPHeader->ip_sum = cksum(IPHeader, ipSize);

      // longest prefix match
      RoutingTableEntry nextHop = m_routingTable.lookup(IPHeader->ip_dst);
      const Interface* nextHopInterface = findIfaceByName(nextHop.ifName);
      std::shared_ptr<ArpEntry> ARP = m_arp.lookup(IPHeader->ip_dst);

      // if not found, send ARP request
      if (ARP == NULL) {
        m_arp.queueArpRequest(IPHeader->ip_dst, IPPacket, nextHopInterface->name);
      }

      // create ethernet header, fill it out, and send
      else {
        ethernet_hdr* ethernetHeader = (ethernet_hdr*) (IPPacket.data());
        ethernetHeader->ether_type = htons(ethertype_ip);
        memcpy(ethernetHeader->ether_dhost, ARP->mac.data(), ETHER_ADDR_LEN);
        memcpy(ethernetHeader->ether_shost, nextHopInterface->addr.data(), ETHER_ADDR_LEN);
        sendPacket(IPPacket, nextHopInterface->name);
      }
    }
  }


  // ARP PACKET
  else if (packetType == ethertype_arp) {
    const arp_hdr* ARPHeader = reinterpret_cast<const arp_hdr*>(ethernetSize + packet.data());

    // ignore the request if IP addresses do not match
    if (iface->ip != ARPHeader->arp_tip) {
      std::cerr << "IP addresses do not match. Ignoring." << std::endl;
      return;
    }

    // figure out if ARP request or ARP reply
    uint16_t arpType = ntohs(ARPHeader->arp_op);
    
    // handling ARP Reply
    if (arpType == arp_op_reply) {
      Buffer MACAddress(ETHER_ADDR_LEN);
      memcpy(MACAddress.data(), ARPHeader->arp_sha, ETHER_ADDR_LEN);

      if (m_arp.lookup(ARPHeader->arp_sip) == NULL) {
        std::shared_ptr<ArpRequest> request = m_arp.insertArpEntry(MACAddress, ARPHeader->arp_sip);
        // remove pending requests from queue
        m_arp.removeArpRequest(request);

        // if there are still packets in queue that correspond with the reply, send them out
        if (request != NULL) {
          for (std::list<PendingPacket>::iterator i = request->packets.begin(); i != request->packets.end(); i++) {
            ethernet_hdr* ethernetHeader = (ethernet_hdr*) i->packet.data();
            memcpy(ethernetHeader->ether_dhost, ARPHeader->arp_sha, ETHER_ADDR_LEN);
            memcpy(ethernetHeader->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
            sendPacket(i->packet, i->iface);
          }
        }
      }
    }

    // handling ARP request
    else if (arpType == arp_op_request) {
      // create ethernet and arp headers, then populate buffer with them
      ethernet_hdr ethernetHeader;
      arp_hdr replyARPHeader;

      replyARPHeader.arp_pln = 4;
      replyARPHeader.arp_sip = iface->ip;
      replyARPHeader.arp_tip = ARPHeader->arp_sip;
      replyARPHeader.arp_hln = ETHER_ADDR_LEN;
      replyARPHeader.arp_hrd = htons(arp_hrd_ethernet);
      replyARPHeader.arp_op = htons(arp_op_reply);
      replyARPHeader.arp_pro = htons(ethertype_ip);
      memcpy(replyARPHeader.arp_tha, &(ARPHeader->arp_sha), ETHER_ADDR_LEN);
      memcpy(replyARPHeader.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);

      ethernetHeader.ether_type = htons(ethertype_arp);
      memcpy(ethernetHeader.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(ethernetHeader.ether_dhost, &(ARPHeader->arp_sha), ETHER_ADDR_LEN);

      Buffer packetBuffer(arpSize + ethernetSize);
      memcpy(packetBuffer.data(), &ethernetHeader, ethernetSize);
      memcpy(packetBuffer.data() + ethernetSize, &replyARPHeader, arpSize);
      sendPacket(packetBuffer, iface->name);
    }

    // error handling - not ARP request or reply
    else {
      std::cerr << "Not an ARP request or reply. Ignoring." << std::endl;
    }
  }

  else {
    std::cerr << "Packet is not IPv4 or ARP. Ignoring." << std::endl;
    return;
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
