package main

import (
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

var (
	ip   string
	port string
	dir  string
)


func printOption(short, longWithVal, desc string, def ...string) {
    line := fmt.Sprintf("  %-3s %-18s %s", short+",", longWithVal, desc)
    if len(def) > 0 && def[0] != "" {
        line += fmt.Sprintf(" (default \"%s\")", def[0])
    }
    fmt.Println(line)
}

func getTemplatePath() string {
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		sourceDir := filepath.Dir(filename)
		templatePath := filepath.Join(sourceDir, "templates/index.html")
		if _, err := os.Stat(templatePath); err == nil {
			return templatePath
		}
	}

	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		templatePath := filepath.Join(exeDir, "templates/index.html")
		return templatePath
	}

	return "templates/index.html"
}

func getStaticDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		sourceDir := filepath.Dir(filename)
		staticPath := filepath.Join(sourceDir, "static")
		if _, err := os.Stat(staticPath); err == nil {
			return staticPath
		}
	}

	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		staticPath := filepath.Join(exeDir, "static")
		return staticPath
	}

	return "static"
}

func logRequest(r *http.Request, status int) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
    timestamp := time.Now().Format("02/Jan/2006 15:04:05")
    log.Printf("%s - - [%s] \"%s %s %s\" %d -",
        clientIP,
        timestamp,
        r.Method,
        r.URL.Path,
        r.Proto,
        status,
    )
}

func validatePort(p string) bool {
	portNum := 0
	_, err := fmt.Sscanf(p, "%d", &portNum)
	if err != nil {
		return false
	}
	return portNum > 0 && portNum <= 65535
}

func checkIPAddress(ip string) bool {
	if ip == "0.0.0.0" {
		return true
	}
	if net.ParseIP(ip) == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var localIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				localIP = v.IP
			case *net.IPAddr:
				localIP = v.IP
			}
			if localIP.String() == ip {
				return true
			}
		}
	}
	return false
}

func checkPortAvailable(ip, port string) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		if isAddrInUse(err) {
			return fmt.Errorf("Port %s is already in use", port)
		}
		return err
	}
	ln.Close()
	return nil
}

func isAddrInUse(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		if syscallErr, ok := opErr.Err.(*os.SyscallError); ok {
			if errno, ok := syscallErr.Err.(syscall.Errno); ok {
				if runtime.GOOS == "windows" {
					return errno == 10048 // WSAEADDRINUSE
				}
				return errno == syscall.EADDRINUSE
			}
		}
	}
	return false
}

func main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
    flag.CommandLine.SetOutput(io.Discard)
    
    flag.StringVar(&ip, "ip", "0.0.0.0", "")
    flag.StringVar(&ip, "i", "0.0.0.0", "")
    flag.StringVar(&port, "port", "8000", "")
    flag.StringVar(&port, "p", "8000", "")
    flag.StringVar(&dir, "dir", ".", "")
    flag.StringVar(&dir, "d", ".", "")

	printHeader := func() {
		banner := `
░▀█▀░█▀▄░█▀█░█▀▀░█▄█░█▀▀░▀█▀░▀█▀░█▀█
░░█░░█▀▄░█▀█░▀▀█░█░█░█▀▀░░█░░░█░░█░█
░░▀░░▀░▀░▀░▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░▀▀▀

	   Version 0.9

		`
		fmt.Println(banner)
    }

    flag.Usage = func() {
		fmt.Println("Usage: myapp [-i IP] [-p PORT] [-d DIRECTORY]\n")
		fmt.Println("Options:")
		printOption("-i", "--ip IP", "IP address to bind to", "0.0.0.0")
		printOption("-p", "--port PORT", "Port number to listen on", "8000")
		printOption("-d", "--dir DIRECTORY", "Directory to serve", ".")
		printOption("-h", "--help", "Help menu")
    }
	
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		printHeader()
		fmt.Println("\033[31mInvalid parameter. \033[0m\n")
		flag.Usage()
		os.Exit(0)
	}


    if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			printHeader()
            flag.Usage()
            os.Exit(0)
        }
        printHeader()
        fmt.Println("\033[31mError:", err, "\033[0m\n")
        flag.Usage()
        os.Exit(0)
    }

	if !validatePort(port) {
		fmt.Println("Invalid port number. Must be between 1-65535")
		os.Exit(0)
	}

	if !checkIPAddress(ip) {
		fmt.Println("Interface does not exist")
		os.Exit(0)
	}

	if err := checkPortAvailable(ip, port); err != nil {
		fmt.Printf("Cannot start server: %v\n", err)
		os.Exit(0)
	}

	var err error
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Printf("Directory '%s' not found, creating '%s'\n", dir, dir)
		
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Println("Failed to create directory:", err)
			os.Exit(0)
		}
	}

	dir, err = filepath.Abs(dir)
	if err != nil {
		fmt.Println("Invalid directory path:", err)
		os.Exit(0)
	}

	if runtime.GOOS == "windows" {
		dir = filepath.Clean(dir)
		if len(dir) == 2 && dir[1] == ':' {
			dir += string(filepath.Separator)
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n\n\033[31mKeyboard interrupt. Exiting...\033[0m\n")
		os.Exit(0)
	}()

	fmt.Printf("Serving %s on http://%s:%s\n", dir, ip, port)

	staticDir := getStaticDir()

	http.HandleFunc("/", wrapHandler(fileHandler))
	http.HandleFunc("/upload", wrapHandler(uploadHandler))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err = http.ListenAndServe(ip+":"+port, nil)
	if err != nil {
		log.Println(err)
		os.Exit(0)
	}
}

func wrapHandler(handler func(http.ResponseWriter, *http.Request) int) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        status := handler(w, r)
        if status != 0 {
            logRequest(r, status)
        }
    }
}

func renderError(w http.ResponseWriter, status int, path string, message string) {
	w.WriteHeader(status)
	tmpl := template.Must(template.ParseFiles(getTemplatePath()))
	tmpl.Execute(w, map[string]interface{}{
		"Files":       []map[string]string{},
		"CurrentPath": path,
		"Error":       message,
		"CanUpload":   false,
	})
}

func cleanURLPath(path string) string {
	path = filepath.ToSlash(filepath.Clean(path))
	path = "/" + strings.TrimLeft(path, "/")
	return strings.ReplaceAll(path, "//", "/")
}

func fileHandler(w http.ResponseWriter, r *http.Request) int {
	requestedPath := cleanURLPath(r.URL.Path)

	fsPath := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(requestedPath, "/")))

	absPath, err := filepath.Abs(fsPath)
	if err != nil {
		renderError(w, http.StatusBadRequest, requestedPath, "Invalid path")
		return http.StatusBadRequest
	}

	if !strings.HasPrefix(absPath, dir) {
		renderError(w, http.StatusForbidden, requestedPath, "Access denied")
		return http.StatusForbidden
	}

	var fileLinks []map[string]string
	if requestedPath != "/" {
		parent := filepath.Dir(requestedPath)
		if parent == "." {
			parent = "/"
		}
		parent = cleanURLPath(parent)
		fileLinks = append(fileLinks, map[string]string{
			"Name": "[..]",
			"Link": parent,
		})
	}

	info, err := os.Stat(absPath)
	if err != nil {
        if os.IsNotExist(err) {
            tmpl := template.Must(template.ParseFiles(getTemplatePath()))
            tmpl.Execute(w, map[string]interface{}{
                "Files":       fileLinks, // Only contains [..]
                "CurrentPath": requestedPath,
                "Error":       "Path not found: " + requestedPath,
                "CanUpload":   false,
            })
            return http.StatusNotFound
        }

		if os.IsPermission(err) {
			tmpl := template.Must(template.ParseFiles(getTemplatePath()))
			tmpl.Execute(w, map[string]interface{}{
				"Files":       fileLinks, // Only contains [..]
				"CurrentPath": requestedPath,
				"Error":       "Not enough privileges to read directory",
				"CanUpload":   false,
			})
			return http.StatusForbidden
		}
		renderError(w, http.StatusNotFound, requestedPath, "Path not found: "+requestedPath)
		return http.StatusNotFound
	}

	if !info.IsDir() {
        logRequest(r, http.StatusOK)
        
        file, err := os.Open(absPath)
        if err != nil {
            if os.IsPermission(err) {
                renderError(w, http.StatusForbidden, requestedPath, "Not enough privileges to read file")
                return http.StatusForbidden
            }
            renderError(w, http.StatusInternalServerError, requestedPath, "Unable to access file")
            return http.StatusInternalServerError
        }
        defer file.Close()

        w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(absPath))
        w.Header().Set("Content-Type", "application/octet-stream")
        http.ServeContent(w, r, filepath.Base(absPath), info.ModTime(), file)
        return 0
    
	}

	_, readErr := os.ReadDir(absPath)
	canRead := readErr == nil || !os.IsPermission(readErr)
	canUpload := canRead

	if canRead {
		testFile := filepath.Join(absPath, ".permcheck")
		if f, err := os.Create(testFile); err == nil {
			f.Close()
			os.Remove(testFile)
		} else if os.IsPermission(err) {
			canUpload = false
		}
	}

	if !canRead {
		tmpl := template.Must(template.ParseFiles(getTemplatePath()))
		tmpl.Execute(w, map[string]interface{}{
			"Files":       fileLinks,
			"CurrentPath": requestedPath,
			"Error":       "Not enough privileges to read directory",
			"CanUpload":   false,
		})
		return http.StatusForbidden
	}

	entries, err := os.ReadDir(absPath)
	if err != nil {
		renderError(w, http.StatusInternalServerError, requestedPath, "Unable to read directory")
		return http.StatusInternalServerError
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() && !entries[j].IsDir() {
			return true
		} else if !entries[i].IsDir() && entries[j].IsDir() {
			return false
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})

	for _, entry := range entries {
		name := entry.Name()
		displayName := name
		link := filepath.Join(requestedPath, name)
		if entry.IsDir() {
			displayName += "/"
			link += "/"
		}
		fileLinks = append(fileLinks, map[string]string{
			"Name": displayName,
			"Link": cleanURLPath(link),
		})
	}

	tmpl := template.Must(template.ParseFiles(getTemplatePath()))
	tmpl.Execute(w, map[string]interface{}{
		"Files":       fileLinks,
		"CurrentPath": requestedPath,
		"CanUpload":   canUpload,
	})
	return http.StatusOK
}

func uploadHandler(w http.ResponseWriter, r *http.Request) int {
    logRequest(r, http.StatusOK)

    err := r.ParseMultipartForm(10 << 20)
    if err != nil {
        renderError(w, http.StatusBadRequest, r.URL.Path, "Failed to parse form")
        return http.StatusBadRequest
    }

    file, handler, err := r.FormFile("file")
    if err != nil {
        renderError(w, http.StatusBadRequest, r.URL.Path, "Error retrieving file")
        return http.StatusBadRequest
    }
    defer file.Close()

    uploadPath := cleanURLPath(r.FormValue("path"))
    if uploadPath == "" {
        uploadPath = "/"
    }

    targetDir := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(uploadPath, "/")))
    targetDir, err = filepath.Abs(targetDir)
    if err != nil || !strings.HasPrefix(targetDir, dir) {
        renderError(w, http.StatusForbidden, uploadPath, "Invalid target directory")
        return http.StatusForbidden
    }

    err = os.MkdirAll(targetDir, os.ModePerm)
    if err != nil {
        renderError(w, http.StatusInternalServerError, uploadPath, "Unable to create target directory")
        return http.StatusInternalServerError
    }

    targetPath := filepath.Join(targetDir, filepath.Base(handler.Filename))
    target, err := os.Create(targetPath)
    if err != nil {
        renderError(w, http.StatusInternalServerError, uploadPath, "Unable to save file")
        return http.StatusInternalServerError
    }
    defer target.Close()

    _, err = io.Copy(target, file)
    if err != nil {
        renderError(w, http.StatusInternalServerError, uploadPath, "Failed to write file")
        return http.StatusInternalServerError
    }
    log.Printf("File written to -> %s", targetPath)

    http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
    return 0 
}

func downloadHandler(w http.ResponseWriter, r *http.Request) int {
	requestedPath := cleanURLPath(r.URL.Path)
	relPath := strings.TrimPrefix(requestedPath, "/download")
	fsPath := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(relPath, "/")))

	absPath, err := filepath.Abs(fsPath)
	if err != nil {
		renderError(w, http.StatusBadRequest, requestedPath, "Invalid path")
		return http.StatusBadRequest
	}

	if !strings.HasPrefix(absPath, dir) {
		renderError(w, http.StatusForbidden, requestedPath, "Access denied")
		return http.StatusForbidden
	}

	file, err := os.Open(absPath)
	if err != nil {
		if os.IsPermission(err) {
			renderError(w, http.StatusForbidden, requestedPath, "Not enough privileges to read file")
			return http.StatusForbidden
		}
		if os.IsNotExist(err) {
			renderError(w, http.StatusNotFound, requestedPath, "File not found: "+requestedPath)
			return http.StatusNotFound
		}
		renderError(w, http.StatusInternalServerError, requestedPath, "Unable to access file")
		return http.StatusInternalServerError
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		renderError(w, http.StatusInternalServerError, requestedPath, "Unable to get file information")
		return http.StatusInternalServerError
	}
	if fileInfo.IsDir() {
		renderError(w, http.StatusBadRequest, requestedPath, "Path is a directory")
		return http.StatusBadRequest
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(absPath))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, absPath)
	return http.StatusOK
}