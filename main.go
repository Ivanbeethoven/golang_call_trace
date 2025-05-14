package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

func worker1(wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Println("Worker 1: Starting")
	time.Sleep(1 * time.Second) // 模拟延迟

	// 系统调用顺序 1
	err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	if err != nil {
		fmt.Println("Worker 1: Error sending SIGTERM", err)
	} else {
		fmt.Println("Worker 1: Sent SIGTERM to self")
	}

	// 创建一个临时文件
	file, err := os.CreateTemp("", "worker1")
	if err != nil {
		fmt.Println("Worker 1: Error creating temp file", err)
		return
	}
	defer file.Close()
	fmt.Println("Worker 1: Created temp file:", file.Name())
}

func worker2(wg *sync.WaitGroup) {
	defer wg.Done()

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

func worker3(wg *sync.WaitGroup) {
	defer wg.Done()

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

func main() {
	var wg sync.WaitGroup

	fmt.Println("Main: Starting workers")

	wg.Add(3)
	go worker1(&wg)
	go worker2(&wg)
	go worker3(&wg)

	wg.Wait()
	fmt.Println("Main: All workers done")
}
