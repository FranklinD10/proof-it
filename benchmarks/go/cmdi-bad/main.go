package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func ping(c *gin.Context) {
	var req struct {
		Host string `json:"host"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+req.Host).CombinedOutput()
	c.String(200, string(out))
}
