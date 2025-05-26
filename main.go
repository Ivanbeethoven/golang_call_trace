package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func hello() {
	// Get goroutine ID from runtime stack
	gid := func() int64 {
		var buf [64]byte
		n := runtime.Stack(buf[:], false)
		idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
		id, _ := strconv.ParseInt(idField, 10, 64)
		return id
	}()
	fmt.Printf("Current Goroutine ID: %d\n", gid)
}


func worker1(wg *sync.WaitGroup) {
	for {
		fmt.Println("Worker 1: Starting")
		time.Sleep(1 * time.Second) // 模拟延迟
		hello() // 打印当前 goroutine ID
		// 系统调用顺序 1
		uid := syscall.Getuid()
		fmt.Printf("Worker 1: Current user ID: %d\n", uid)
		// Get group ID as well
		gid := syscall.Getgid()
		fmt.Printf("Worker 1: Current group ID: %d\n", gid)

		// 创建一个临时文件
		file, err := os.CreateTemp("", "worker1")
		if err != nil {
			fmt.Println("Worker 1: Error creating temp file", err)
			return
		}
		file.Close()
		fmt.Println("Worker 1: Created temp file:", file.Name())
	}
}

func worker2(wg *sync.WaitGroup) {
	for  {
		fmt.Println("Worker 2: Starting")
		time.Sleep(2 * time.Second) // 模拟延迟

		// 系统调用顺序 2
		_, err := os.Stat("/")
		if err != nil {
			fmt.Println("Worker 2: Error checking root dir", err)
		} else {
			fmt.Println("Worker 2: Checked root directory")
		}

		// 获取当前进程的 PID
		pid := syscall.Getpid()
		fmt.Println("Worker 2: Current PID:", pid)
}
}

func worker3(wg *sync.WaitGroup) {
	for {
		fmt.Println("Worker 3: Starting")
		time.Sleep(3 * time.Second) // 模拟延迟

		// 系统调用顺序 3
		err := syscall.Chdir("/tmp")
		if err != nil {
			fmt.Println("Worker 3: Error changing directory", err)
		} else {
			fmt.Println("Worker 3: Changed directory to /tmp")
		}

		// 获取当前工作目录
		cwd, _ := os.Getwd()
		fmt.Println("Worker 3: Current working directory:", cwd)
	}

}

func main() {
	var wg sync.WaitGroup

	fmt.Println("Main: Starting workers")

	wg.Add(3)
	go worker1(&wg)
	go worker2(&wg)
	go worker3(&wg)

	for{

	}
	fmt.Println("Main: All workers done")
}
