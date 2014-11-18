package main

import (
	"strings"
	"sync"
)

type ARPData struct {
	Operation        uint16
	SenderMACAddress string
	SenderIPAddress  string
	TargetMACAddress string
	TargetIPAddress  string
}

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

func (s *ARPStore) AllARPData() map[string]*ARPData {
	s.RLock()
	defer s.RUnlock()

	mapCopy := make(map[string]*ARPData)

	for key, data := range s.arpData {
		mapCopy[key] = data
	}

	return mapCopy
}

func (s *ARPStore) Len() int {
	s.RLock()
	defer s.RUnlock()

	return len(s.arpData)
}
