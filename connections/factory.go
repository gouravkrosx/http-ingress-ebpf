/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package connections

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"http_ingress/structs"
	"http_ingress/util"

	"go.uber.org/zap"
)

// Factory is a routine-safe container that holds a trackers with unique ID, and able to create new tracker.
type Factory struct {
	connections         map[structs.ConnID]*Tracker
	inactivityThreshold time.Duration
	mutex               *sync.RWMutex
	logger              *zap.Logger
}

// NewFactory creates a new instance of the factory.
func NewFactory(inactivityThreshold time.Duration, logger *zap.Logger) *Factory {
	return &Factory{
		connections:         make(map[structs.ConnID]*Tracker),
		mutex:               &sync.RWMutex{},
		inactivityThreshold: inactivityThreshold,
		logger:              logger,
	}
}

func (factory *Factory) HandleReadyConnections() {

	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	var trackersToDelete []structs.ConnID
	for connID, tracker := range factory.connections {
		if tracker.IsComplete() {
			trackersToDelete = append(trackersToDelete, connID)
			if len(tracker.sentBuf) == 0 && len(tracker.recvBuf) == 0 {
				continue
			}

			// fmt.Printf(""========================>\nFound HTTP payload\nRequest->\n%s\n\nResponse->\n%s\n\n<========================\n", tracker.recvBuf, tracker.sentBuf)
			fmt.Printf("========================>\nFound HTTP payload\nResponse->\n%s\n\n<========================\n", tracker.sentBuf)

			parsedHttpReq, err := util.ParseHTTPRequest(tracker.recvBuf)
			if err != nil {
				factory.logger.Error("failed to parse the http request from byte array", zap.Error(err))
				continue
			}

			fmt.Printf("Request:%v\n", parsedHttpReq)

			// _, err = io.ReadAll(parsedHttpReq.Body)
			// if err != nil {
			// 	factory.logger.Error("failed to read the http request body", zap.Error(err))
			// 	return
			// }

			// Check if the request contains a file upload
			contentType := parsedHttpReq.Header.Get("Content-Type")
			mediatype, params, err := mime.ParseMediaType(contentType)
			if err != nil {
				factory.logger.Error("failed to parse the content type", zap.Error(err))
				return
			}

			if strings.HasPrefix(mediatype, "multipart/") {
				// Expect a file upload, so process it
				mr := multipart.NewReader(parsedHttpReq.Body, params["boundary"])

				// Assuming there's only one file
				part, err := mr.NextPart()
				if err != nil {
					factory.logger.Error("failed to get the next part from multipart reader", zap.Error(err))
					return
				}

				// Extract the filename from the part's header (Assuming it's there)
				filename := part.FileName()
				if filename == "" {
					factory.logger.Error("failed to extract filename", zap.String("err", "filename not found in part header"))
					return
				}

				// Create a new file with the extracted filename
				file, err := os.Create(filename)
				if err != nil {
					factory.logger.Error("failed to create file", zap.Error(err), zap.String("filename", filename))
					return
				}
				defer file.Close()

				// Copy the part's body to the new file
				_, err = io.Copy(file, part)
				if err != nil {
					factory.logger.Error("failed to write to file", zap.Error(err), zap.String("filename", filename))
					return
				}

				fmt.Printf("File %s has been created\n", filename)
			}

			// factory.logger.Debug(string(reqBody))
			finalResponseData := util.ExtractLastResponse(tracker.sentBuf)
			var parsedHttpRes *http.Response
			if finalResponseData != nil || len(finalResponseData) != 0 {

				parsedHttpRes, err = util.ParseHTTPResponse(finalResponseData, parsedHttpReq)
				if err != nil {
					factory.logger.Error("failed to parse the http response from byte array", zap.Error(err))
					continue
				}
			} else {
				factory.logger.Error("failed to locate the last HTTP response")
			}

			fmt.Printf("Response:%v\n", parsedHttpRes)

			respBody, err := io.ReadAll(parsedHttpRes.Body)
			parsedHttpRes.Body.Close()

			if err != nil {
				factory.logger.Error("failed to read the http response body", zap.Error(err))
				return
			}

			factory.logger.Debug("ResponseBody:" + string(respBody))

		} else if tracker.Malformed() || tracker.IsInactive(factory.inactivityThreshold) {
			trackersToDelete = append(trackersToDelete, connID)
		}
	}

	// Delete all the processed trackers.
	for _, key := range trackersToDelete {
		delete(factory.connections, key)
	}
}

// GetOrCreate returns a tracker that related to the given connection and transaction ids. If there is no such tracker
// we create a new one.
func (factory *Factory) GetOrCreate(connectionID structs.ConnID) *Tracker {
	factory.mutex.Lock()
	defer factory.mutex.Unlock()
	tracker, ok := factory.connections[connectionID]
	if !ok {
		factory.connections[connectionID] = NewTracker(connectionID, factory.logger)
		return factory.connections[connectionID]
	}
	return tracker
}
