package main

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
	}
}

func worker2(wg *sync.WaitGroup) {
	for  {
		fmt.Println("Worker 2: Starting")
		time.Sleep(2 * time.Second) // 模拟延迟

		hello() // 打印当前 goroutine ID
	}

}

func worker3(wg *sync.WaitGroup) {
	for {
		fmt.Println("Worker 3: Starting")
		time.Sleep(3 * time.Second) // 模拟延迟

		hello() // 打印当前 goroutine ID
	}

}

func main() {
	var wg sync.WaitGroup

	fmt.Println("Main: Starting workers")

	wg.Add(30)
	for i := 0; i < 10; i++ {
		go worker1(&wg)
		go worker2(&wg)
		go worker3(&wg)
	}

	for{

	}
	fmt.Println("Main: All workers done")
}
