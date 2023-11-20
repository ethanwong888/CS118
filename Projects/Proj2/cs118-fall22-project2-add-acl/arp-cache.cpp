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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // FILL THIS IN
  std::list<std::shared_ptr<ArpEntry>>::iterator cacheIterator = m_cacheEntries.begin();
  std::list<std::shared_ptr<ArpRequest>>::iterator ARPIterator = m_arpRequests.begin();
  auto currentTime = steady_clock::now();
  size_t ARPSize = sizeof(arp_hdr);
  size_t ethernetSize = sizeof(ethernet_hdr);

  // loop through the cache and eliminate stale ARP info
  while (cacheIterator != m_cacheEntries.end()) {
    // if the cache entry is stale, erase it
    if (((*cacheIterator)->isValid) == false) {
      cacheIterator = m_cacheEntries.erase(cacheIterator);
    } 
    // if the cache entry is valid, just move on to the next one
    else {
      cacheIterator++;
    }
  }

  // Keep retransmitting ARP request until router receives a reply OR router has retransmitted at least 5 times
  while (ARPIterator != m_arpRequests.end()) {
    // transmit ARP request
    if ((*ARPIterator)->nTimesSent < 5) {
      std::string interfaceName = (*ARPIterator)->packets.front().iface;
      const Interface* interface = m_router.findIfaceByName(interfaceName);

      arp_hdr ARPHeader;
      memcpy(ARPHeader.arp_sha, interface->addr.data(), ETHER_ADDR_LEN);
      memset(ARPHeader.arp_tha, 0xFF, ETHER_ADDR_LEN);
      ARPHeader.arp_hln = ETHER_ADDR_LEN;
      ARPHeader.arp_sip = interface->ip;
      ARPHeader.arp_op = htons(arp_op_request);
      ARPHeader.arp_hrd = htons(arp_hrd_ethernet);
      ARPHeader.arp_tip = (*ARPIterator)->ip;
      ARPHeader.arp_pln = 4;
      ARPHeader.arp_pro = htons(ethertype_ip);      

      ethernet_hdr ethernetHeader;
      memcpy(ethernetHeader.ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
      memset(ethernetHeader.ether_dhost, 0xFF, ETHER_ADDR_LEN);
      ethernetHeader.ether_type = htons(ethertype_arp);

      Buffer ARPBuffer(ARPSize + ethernetSize);
      memcpy(ARPBuffer.data(), &ethernetHeader, ethernetSize);
      memcpy(ARPBuffer.data() + ethernetSize, &ARPHeader, ARPSize);

      m_router.sendPacket(ARPBuffer, interfaceName);
      std::cerr << "ARP Request Sent" << std::endl;

      (*ARPIterator)->nTimesSent++;
      (*ARPIterator)->timeSent = currentTime;
      ARPIterator++;
    }

    else {
      ARPIterator = m_arpRequests.erase(ARPIterator);
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueArpRequest(uint32_t ip, const Buffer& packet, const std::string& interface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, interface});
  return *request;
}

void
ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
