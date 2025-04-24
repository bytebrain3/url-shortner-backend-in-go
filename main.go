package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Define the URL model for PostgreSQL
type URL struct {
	ID        uint   `gorm:"primaryKey"`
	ShortCode string `gorm:"uniqueIndex"`
	FullURL   string `gorm:"not null"`
	CreatedAt time.Time
}

type FullURL struct {
	URL string `json:"url"`
}

func createShortUrl() string {
	rand.Seed(time.Now().UnixNano())
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	shortURL := ""
	for i := 0; i < 6; i++ {
		shortURL += string(chars[rand.Intn(len(chars))])
	}
	return shortURL
}

var ctx = context.Background()
var redisClient *redis.Client
var db *gorm.DB

// Initialize Redis connection
func initRedis() {
	opt, err := redis.ParseURL("redis://default:y7NxahNfIelbY0gBISOIP2P7zK5T15hX@redis-15351.c15.us-east-1-4.ec2.redns.redis-cloud.com:15351")
	if err != nil {
		log.Fatal("❌ Redis URL parsing error:", err)
	}
	redisClient = redis.NewClient(opt)

	// Test Redis connection
	err = redisClient.Set(ctx, "ping", "pong", 0).Err()
	if err != nil {
		log.Fatalf("❌ Redis connection failed: %v", err)
	}
	val, err := redisClient.Get(ctx, "ping").Result()
	if err != nil {
		log.Fatalf("❌ Redis GET failed: %v", err)
	}
	fmt.Println("✅ Redis Connected! Response:", val)
}

// Initialize PostgreSQL connection and auto-migrate the URL model
func initPostgress() {
	dsn := "postgresql://url-shortner_owner:npg_c3FaYpn5XvgV@ep-bold-smoke-a4dcqj6r-pooler.us-east-1.aws.neon.tech/url-shortner?sslmode=require"

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("❌ Unable to connect to database: %v", err)
	}
	fmt.Println("✅ Connected to PostgreSQL!")

	// Auto migrate URL model
	err = db.AutoMigrate(&URL{})
	if err != nil {
		log.Fatalf("❌ Auto migration failed: %v", err)
	}
}

func main() {
	app := fiber.New()

	initRedis()
	initPostgress()

	// Middleware to log every request
	app.Use(func(c *fiber.Ctx) error {
		fmt.Printf("📥 %s %s\n", c.Method(), c.Path())
		return c.Next()
	})

	// Root check
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "I am still alive 🙂",
			"status":  200,
		})
	})

	// POST: Accept full URL, shorten, and store
	app.Post("/create-short-url", func(c *fiber.Ctx) error {
		var req FullURL

		if err := c.BodyParser(&req); err != nil || req.URL == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "URL is required!",
				"status":  400,
			})
		}

		// Generate short code
		shortURL := createShortUrl()

		// Store in Redis with 24-hour expiration
		err := redisClient.Set(ctx, shortURL, req.URL, 0).Err()
		if err != nil {
			log.Printf("❌ Failed to store in Redis: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to save to Redis",
				"status":  500,
			})
		}

		// Also store in PostgreSQL for permanent storage
		urlRecord := URL{ShortCode: shortURL, FullURL: req.URL}
		if err := db.Create(&urlRecord).Error; err != nil {
			log.Printf("❌ Failed to store in PostgreSQL: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to save to database",
				"status":  500,
			})
		}

		// Respond with short URL info
		return c.JSON(fiber.Map{
			"message": "URL shortened successfully",
			"data": fiber.Map{
				"short": shortURL,
				"full":  req.URL,
			},
			"status": 200,
		})
	})

	// GET: Redirect from shortened URL to full URL
	app.Get("/r/:code", func(c *fiber.Ctx) error {
		shortCode := c.Params("code")

		// Check Redis first
		fullURL, err := redisClient.Get(ctx, shortCode).Result()
		if err == redis.Nil {
			// If not found in Redis, check PostgreSQL
			var urlRecord URL
			if err := db.Where("short_code = ?", shortCode).First(&urlRecord).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					// Not found in both Redis and PostgreSQL
					return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
						"message": "Short URL not found",
						"status":  404,
					})
				}
				log.Printf("❌ PostgreSQL query error: %v", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"message": "Server error",
					"status":  500,
				})
			}
			// Store in Redis for faster future access
			redisClient.Set(ctx, shortCode, urlRecord.FullURL, 0).Err()
			fullURL = urlRecord.FullURL
		} else if err != nil {
			// Redis error
			log.Printf("❌ Redis GET error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Server error",
				"status":  500,
			})
		}

		// Redirect to the full URL
		return c.Redirect(fullURL, fiber.StatusFound)
	})

	log.Fatal(app.Listen(":3000"))
}
