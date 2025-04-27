package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/mssola/user_agent"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Define the URL model for PostgreSQL
type URL struct {
	ID          uint   `gorm:"primaryKey"`
	ShortCode   string `gorm:"uniqueIndex"`
	FullURL     string `gorm:"not null"`
	CreatedAt   time.Time
	AnaliticsID uint      `gorm:"not null"`
	Analitics   Analitics `gorm:"foreignKey:AnaliticsID"`
	UserID      uint      `gorm:"not null"`
	User        User      `gorm:"foreignKey:UserID"`
}

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"uniqueIndex"`
	Password  string `gorm:"not null"`
	Email     string `gorm:"uniqueIndex"` // Made exported
	CreatedAt time.Time
}

// analitics struct for URL clicks
type Analitics struct {
	ID                 uint           `gorm:"primaryKey"`
	ShortCode          string         `gorm:"not null"`
	Click              int            `gorm:"default:0"`
	IPsWhoVisited      pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
	BrowserWhoVisited  pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
	OSWhoVisited       pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
	DeviceWhoVisited   pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
	ReferrerWhoVisited pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
	LocationWhoVisited pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
}

type FullURL struct {
	URL    string `json:"url"`
	UserID uint   `json:"user_id"` // Added user_id field to the struct
}

type Login struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var ctx = context.Background()
var redisClient *redis.Client
var db *gorm.DB
var jwtSecret = []byte("kobejmorithiknai")

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
	/* err = db.AutoMigrate(&User{}, &Analitics{}, &URL{})
	if err != nil {
		log.Fatalf("❌ Auto migration failed: %v", err)
	} */
}

type CustomTokenJwtStucture struct {
	UID      uint   `json:"userID"`
	USERNAME string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateToken(userID uint, username string) (string, error) {
	claims := CustomTokenJwtStucture{
		UID:      userID,
		USERNAME: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(240 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func VerifiedToken(tokenString string) (*CustomTokenJwtStucture, error) {
	claims := &CustomTokenJwtStucture{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return claims, nil
}

func createShortUrl() string {
	rand.Seed(time.Now().UnixNano())

	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	length := rand.Intn(4) + 3 // random length between 3 and 6 (3 + [0..3])

	shortURL := make([]byte, length)
	for i := 0; i < length; i++ {
		shortURL[i] = charset[rand.Intn(len(charset))]
	}

	return string(shortURL)
}

func GetVisitorInfo(c *fiber.Ctx) (browser, os, device, ip string) {
	ua := user_agent.New(c.Get("User-Agent"))
	name, version := ua.Browser()
	browser = name + " " + version
	os = ua.OS()
	if ua.Mobile() {
		device = "Mobile"
	} else {
		device = "Desktop"
	}
	ip = c.IP()

	return
}

func main() {
	app := fiber.New()

	initRedis()
	initPostgress()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000/",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true, // ← must be true to set cookies
	}))

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

		fmt.Println(req)

		// Generate short code
		shortURL := createShortUrl()
		analiticsRecord := Analitics{ShortCode: shortURL}
		if err := db.Create(&analiticsRecord).Error; err != nil {
			log.Printf("❌ Failed to store analitics in PostgreSQL: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to save to database",
				"status":  500,
			})
		}
		// Also store in PostgreSQL for permanent storage
		urlRecord := URL{
			ShortCode:   shortURL,
			FullURL:     req.URL,
			UserID:      req.UserID, // from request
			AnaliticsID: analiticsRecord.ID,
		}

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
		browser, os, device, _ := GetVisitorInfo(c)
		ip := c.IP()

		// Get Referer header
		referer := c.Get("Referer")

		// Default to unknown if missing
		fromSite := "unknown"
		if referer != "" {
			if u, err := url.Parse(referer); err == nil {
				fromSite = strings.TrimPrefix(u.Hostname(), "www.")
			}
		}

		/* type Analitics struct {
			ID                 uint           `gorm:"primaryKey"`
			ShortCode          string         `gorm:"not null"`
			Click              int            `gorm:"default:0"`
			IPsWhoVisited      pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
			BrowserWhoVisited  pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
			OSWhoVisited       pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
			DeviceWhoVisited   pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
			ReferrerWhoVisited pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
			LocationWhoVisited pq.StringArray `gorm:"type:text[]"` // Use `pq` package for Postgres arrays
		} */

		var data Analitics

		if err := db.FirstOrCreate(&data, Analitics{ShortCode: shortCode}).Error; err != nil {
			return err
		}
		data.Click++
		data.BrowserWhoVisited = append(data.BrowserWhoVisited, browser)
		data.OSWhoVisited = append(data.OSWhoVisited, os)
		data.DeviceWhoVisited = append(data.DeviceWhoVisited, device)
		data.ReferrerWhoVisited = append(data.ReferrerWhoVisited, fromSite)
		data.IPsWhoVisited = append(data.IPsWhoVisited, ip)

		if err := db.Model(&data).Updates(map[string]interface{}{
			"browser_who_visited":  data.BrowserWhoVisited,
			"os_who_visited":       data.OSWhoVisited,
			"device_who_visited":   data.DeviceWhoVisited,
			"referrer_who_visited": data.ReferrerWhoVisited,
			"IPsWhoVisited":        data.IPsWhoVisited,
			"Click":                data.Click,
		}).Error; err != nil {
			return err
		}

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
			if err := redisClient.Set(ctx, shortCode, urlRecord.FullURL, 24*time.Hour).Err(); err != nil {
				log.Printf("❌ Failed to cache URL in Redis: %v", err)
			}

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

	app.Get("/health", func(c *fiber.Ctx) error {
		// Check Redis connection
		_, err := redisClient.Ping(ctx).Result()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "❌ Redis connection failed",
				"status":  500,
			})
		}

		// Check PostgreSQL connection
		sqlDB, err := db.DB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "❌ PostgreSQL connection failed",
				"status":  500,
			})
		}
		err = sqlDB.Ping()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "❌ PostgreSQL ping failed",
				"status":  500,
			})
		}

		// Everything is good!
		return c.JSON(fiber.Map{
			"message": "✅ All systems operational",
			"status":  200,
		})
	})
	app.Post("/create-user", func(c *fiber.Ctx) error {
		var user User
		if err := c.BodyParser(&user); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "Invalid request",
				"status":  400,
			})
		}

		if user.Username == "" || user.Password == "" || user.Email == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "Username, password, and email are required",
				"status":  400,
			})
		}

		// Check if user already exists
		var existingUser User
		if err := db.Where("username = ? OR email = ?", user.Username, user.Email).First(&existingUser).Error; err == nil {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"message": "User already exists",
				"status":  409,
			})
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		user.Password = string(hash)
		// `Create` the new user
		if err := db.Create(&user).Error; err != nil {
			log.Printf("❌ Failed to create user: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to create user",
				"status":  500,
			})
		}

		// Generat token

		token, error := GenerateToken(user.ID, user.Username)

		if error != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Token creation failed"})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "token",
			Value:    token,
			Expires:  time.Now().Add(240 * time.Hour),
			HTTPOnly: true,
			Secure:   true,
			SameSite: fiber.CookieSameSiteNoneMode,
		})

		return c.JSON(fiber.Map{
			"message": "User created successfully",
			"status":  200,
		})
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		var login Login
		if err := c.BodyParser(&login); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "Invalid request",
				"status":  400,
			})
		}

		fmt.Printf("name %s email %s password %s ", login.Username, login.Email, login.Password)

		if login.Password == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "Password  required",
				"status":  400,
			})
		}
		if login.Username == "" || login.Email == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"message": "Username or email are required",
				"status":  400,
			})
		}

		// Check is user is exist for login
		var user User
		if err := db.Where("username = ? OR email = ?", login.Username, login.Email).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"message": "Invalid username or email",
					"status":  401,
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Database error",
				"status":  500,
			})
		}

		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password))

		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Incorrect password",
				"status":  401,
			})
		}

		token, err := GenerateToken(user.ID, user.Username)

		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Could not generate token",
				"status":  500,
			})
		}

		c.Cookie(&fiber.Cookie{
			Name:     "token",
			Value:    token,
			Expires:  time.Now().Add(240 * time.Hour),
			HTTPOnly: true,
			Secure:   true,
			SameSite: fiber.CookieSameSiteNoneMode,
		})

		return c.JSON(fiber.Map{
			"message": "Login successful",
			"data": fiber.Map{
				"token": token,
			},
			"status": 200,
		})

	})

	app.Get("/get-all-urls/:id", func(c *fiber.Ctx) error {
		// Access the user ID from the request params
		id := c.Params("id")

		// Declare the URL struct and User struct
		var urls []URL
		var user User

		// Query for the user
		if err := db.Where("ID = ?", id).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"message": "User Not Found!",
					"status":  404,
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Server error",
				"status":  500,
			})
		}

		// Query for all URLs associated with the user and preload related Analitics and User
		if err := db.Preload("Analitics").Preload("User").Where("user_id = ?", user.ID).Find(&urls).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error fetching URLs",
				"status":  500,
			})
		}

		// Return the list of URLs
		return c.JSON(fiber.Map{
			"data":    urls,
			"message": "URLs found successfully",
			"status":  200,
		})
	})

	log.Fatal(app.Listen(":8000"))
}
