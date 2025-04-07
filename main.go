package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// responseRecorder wraps a http.ResponseWriter to capture the status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func main() {
	// Configure logging to stderr
	log.SetOutput(os.Stderr)
	
	// Parse command line arguments
	dataDir := flag.String("data", "./data", "Directory containing files to serve")
	trustDir := flag.String("trust", "./trust", "Directory containing trusted CA certificates")
	listenAddr := flag.String("listen", ":8443", "Address to listen on")
	certFile := flag.String("cert", "server.crt", "Server certificate file")
	keyFile := flag.String("key", "server.key", "Server key file")
	flag.Parse()

	// Verify data directory exists
	if _, err := os.Stat(*dataDir); os.IsNotExist(err) {
		log.Fatalf("Data directory %s does not exist", *dataDir)
	}

	// Verify trust directory exists
	if _, err := os.Stat(*trustDir); os.IsNotExist(err) {
		log.Fatalf("Trust directory %s does not exist", *trustDir)
	}

	// Load trusted CA certificates
	caCertPool := x509.NewCertPool()
	caFiles, err := os.ReadDir(*trustDir)
	if err != nil {
		log.Fatalf("Failed to read trust directory: %v", err)
	}

	for _, file := range caFiles {
		if file.IsDir() {
			continue
		}
		
		caPath := filepath.Join(*trustDir, file.Name())
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			log.Printf("Warning: Failed to read CA certificate %s: %v", caPath, err)
			continue
		}
		
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			log.Printf("Warning: No certificates found in %s", caPath)
		} else {
			log.Printf("Added CA certificate from %s", caPath)
		}
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	
	// Create file server
	fileServer := http.FileServer(http.Dir(*dataDir))
	
	// Setup HTTP server
	server := &http.Server{
		Addr:      *listenAddr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
			recorder := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK, // Default status code
			}
			
			clientIP := r.RemoteAddr
			method := r.Method
			path := r.URL.Path
			
			// Check if client certificate is valid
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
				log.Printf("[FAIL] %s - %s %s - Client certificate missing or invalid", 
					clientIP, method, path)
				http.Error(recorder, "Client certificate required", http.StatusUnauthorized)
				return
			}
			
			clientCert := r.TLS.PeerCertificates[0]
			clientName := clientCert.Subject.CommonName
			
			// Serve the file
			fileServer.ServeHTTP(recorder, r)
			
			// Calculate request duration
			duration := time.Since(startTime)
			
			// Log the request
			status := "SUCCESS"
			if recorder.statusCode >= 400 {
				status = "FAIL"
			}
			
			log.Printf("[%s] %s [CN=%s] - %s %s - %d - %s", 
				status, clientIP, clientName, method, path, 
				recorder.statusCode, duration)
		}),
	}
	
	// Start server
	log.Printf("Starting TLS server on %s", *listenAddr)
	log.Printf("Serving files from %s", *dataDir)
	log.Printf("Requiring client certificates signed by CAs in %s", *trustDir)
	
	if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}