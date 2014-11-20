package main

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type ARPData struct {
	Interface        *net.Interface
	Operation        uint16
	SenderMACAddress string
	SenderIPAddress  string
	TargetMACAddress string
	TargetIPAddress  string
	Time             time.Time
}

type ARPDatas []*ARPData

func (l ARPDatas) Len() int           { return len(l) }
func (l ARPDatas) Swap(i, j int)      { l[i], l[j] = l[j], l[i] }
func (l ARPDatas) Less(i, j int) bool { return l[i].Time.Unix() > l[j].Time.Unix() }

type ARPStore struct {
	sync.RWMutex
	arpData map[string]*ARPData
}

func NewARPStore() *ARPStore {
	return &ARPStore{arpData: make(map[string]*ARPData)}
}

func (s *ARPStore) PutARPData(data *ARPData) (*ARPData, bool) {
	s.Lock()
	defer s.Unlock()

	key := strings.Join([]string{data.SenderIPAddress, data.TargetIPAddress}, ":")

	if existingData, exists := s.arpData[key]; exists {
		return existingData, exists
	} else {
		s.arpData[key] = data
		return nil, false
	}
}

func (s *ARPStore) ARPDataMap() map[string]*ARPData {
	s.RLock()
	defer s.RUnlock()

	mapCopy := make(map[string]*ARPData)

	for key, data := range s.arpData {
		mapCopy[key] = data
	}

	return mapCopy
}

func (s *ARPStore) ARPDataListSorted() []*ARPData {
	s.RLock()
	defer s.RUnlock()

	list := make(ARPDatas, 0)

	for _, data := range s.arpData {
		list = append(list, data)
	}

	sort.Sort(list)

	return list
}

func (s *ARPStore) Len() int {
	s.RLock()
	defer s.RUnlock()

	return len(s.arpData)
}
