package server

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
	"go.uber.org/zap"
)

type Server struct {
	Logger  *zap.SugaredLogger
	DB      *pgx.Conn
	Queries *queries.Queries
}

//go:embed views
var viewsfs embed.FS

// Start the web server
func (s *Server) Start(addr string) error {
	engine := html.NewFileSystem(http.FS(viewsfs), ".html")

	engine.AddFuncMap(template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	})

	app := fiber.New(fiber.Config{
		Views:             engine,
		ViewsLayout:       "views/layouts/root",
		PassLocalsToViews: true,
	})

	// Mount routes
	s.mountRoutes(app)

	// Start!
	return app.Listen(addr)
}

// Mount routes
func (s *Server) mountRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		mostUpvoted, err := s.Queries.MostUpvoted(c.Context(), queries.MostUpvotedParams{Limit: 5})
		if err != nil {
			s.Logger.Errorw("failed to get most upvoted pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get most upvoted pincodes")
		}

		mostDownvoted, err := s.Queries.MostDownvoted(c.Context(), queries.MostDownvotedParams{Limit: 5})
		if err != nil {
			s.Logger.Errorw("failed to get most upvoted pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get most upvoted pincodes")
		}

		return c.Render("views/index", fiber.Map{"MostUpvoted": mostUpvoted, "MostDownvoted": mostDownvoted})
	})

	app.Get("/about", func(c *fiber.Ctx) error {
		return c.Render("views/about", nil)
	})

	app.Get("/contact", func(c *fiber.Ctx) error {
		return c.Render("views/contact", nil)
	})

	app.Get("/leaderboard", func(c *fiber.Ctx) error {
		mostUpvoted, err := s.Queries.MostUpvoted(c.Context(), queries.MostUpvotedParams{Limit: 50})
		if err != nil {
			s.Logger.Errorw("failed to get most upvoted pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get most upvoted pincodes")
		}

		return c.Render("views/board", fiber.Map{"Board": mostUpvoted, "Title": "Leaderboard"})
	})

	app.Get("/looserboard", func(c *fiber.Ctx) error {
		mostDownvoted, err := s.Queries.MostDownvoted(c.Context(), queries.MostDownvotedParams{Limit: 50})
		if err != nil {
			s.Logger.Errorw("failed to get MostDownvoted pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get MostDownvoted pincodes")
		}

		return c.Render("views/board", fiber.Map{"Board": mostDownvoted, "Title": "Looserboard"})
	})

	app.Get("/pincode", func(c *fiber.Ctx) error {
		page, limit := c.QueryInt("page", 1), c.QueryInt("limit", 100)
		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 1
		}
		offset := (page - 1) * limit

		pincodes, err := s.Queries.GetPincodes(c.Context(), queries.GetPincodesParams{
			Limit: int32(limit), Offset: int32(offset),
		})
		if err != nil {
			s.Logger.Errorw("failed to get pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get pincodes")
		}

		return c.Render("views/pincodes", fiber.Map{
			"Pincodes": pincodes,
			"Limit":    limit, "Page": page, "NextPage": page + 1, "PrevPage": page - 1,
		})
	})

	app.Get("/pincode/:pincode", func(c *fiber.Ctx) error {
		var pincode pgtype.Int4
		if pint, err := strconv.ParseInt(c.Params("pincode"), 10, 32); err != nil {
			return c.SendStatus(http.StatusBadRequest)
		} else {
			pincode.Int32 = int32(pint)
			pincode.Valid = true
		}

		pincodeResult, err := s.Queries.GetByPincode(c.Context(), pincode)
		if err != nil {
			s.Logger.Errorw("failed to get pincode", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get pincode")
		}

		if len(pincodeResult) == 0 {
			return c.Status(http.StatusNotFound).SendString("pincode not found")
		}

		// Find all unique states, in 99.99% cases, there will be only one state
		statesMap := make(map[string]bool)
		states := make([]string, 0, len(pincodeResult))
		for _, p := range pincodeResult {
			if statesMap[p.Statename.String] {
				continue
			}
			statesMap[p.Statename.String] = true
			states = append(states, p.Statename.String)
		}

		// Calculate votes
		votes, err := s.Queries.GetPincodeVotes(c.Context(), pincode.Int32)
		if err != nil {
			if err == pgx.ErrNoRows {
				votes.Pincode = pincode.Int32
			} else {
				s.Logger.Errorw("failed to get pincode votes", "error", err)
				return c.Status(http.StatusInternalServerError).SendString("failed to get pincode votes")
			}
		}

		return c.Render("views/pincode", fiber.Map{
			"PostOffices": pincodeResult,
			"Pincode":     pincode,
			"State":       strings.Join(states, "/"),
			"Votes":       votes,
			"TotalVotes":  votes.Upvotes - votes.Downvotes,
		})
	})

	app.Get("/vote", func(c *fiber.Ctx) error {
		pincode := c.QueryInt("pincode")
		pincodeResult, err := s.Queries.GetByPincode(c.Context(), pgtype.Int4{Int32: int32(pincode), Valid: true})
		if err != nil {
			if err == pgx.ErrNoRows {
				return c.Status(http.StatusNotFound).SendString("pincode not found")
			} else {
				s.Logger.Errorw("failed to get pincode", "error", err)
				return c.Status(http.StatusInternalServerError).SendString("failed to get pincode")
			}
		}

		return c.Render("views/vote", fiber.Map{"Pincode": pincode, "Info": pincodeResult, "ClientID": os.Getenv("GOOGLE_CLIENT_ID")})
	})

	app.Post("/google-login", func(c *fiber.Ctx) error {
		// Extract credential from body
		var data map[string]interface{}
		if err := json.Unmarshal(c.Body(), &data); err != nil {
			return c.Status(http.StatusBadRequest).SendString("invalid json")
		}
		credential, ok := data["credential"].(string)
		if !ok {
			return c.Status(http.StatusBadRequest).SendString("invalid json")
		}

		set, err := jwk.Fetch(c.Context(), "https://www.googleapis.com/oauth2/v3/certs")
		if err != nil {
			s.Logger.Errorw("failed to fetch jwk", "error", err)
			return c.SendStatus(http.StatusInternalServerError)
		}

		// Validate credential
		time.Sleep(2 * time.Second) // sleeping to prevent iat validation error
		token, err := jwt.Parse(
			[]byte(credential),
			jwt.WithKeySet(set),
			jwt.WithAudience(os.Getenv("GOOGLE_CLIENT_ID")),
			jwt.WithIssuer("https://accounts.google.com"),
		)
		if err != nil {
			s.Logger.Errorw("failed to parse token", "error", err)
			return c.SendStatus(http.StatusUnauthorized)
		}

		getUser := func() (*queries.User, error) {
			var email, name, pic string
			id, ok := token.Subject()
			if !ok {
				s.Logger.Errorw("failed to parse sub")
				return nil, c.SendStatus(http.StatusBadRequest)
			}
			if err := token.Get("email", &email); err != nil {
				s.Logger.Errorw("failed to parse email", "error", err)
				return nil, c.SendStatus(http.StatusBadRequest)
			}
			if err := token.Get("name", &name); err != nil {
				s.Logger.Errorw("failed to parse name", "error", err)
				return nil, c.SendStatus(http.StatusBadRequest)
			}
			if err := token.Get("picture", &pic); err != nil {
				s.Logger.Errorw("failed to parse picture", "error", err)
				return nil, c.SendStatus(http.StatusBadRequest)
			}

			// Find user
			user, err := s.Queries.GetUserByGoogleID(c.Context(), pgtype.Text{String: id, Valid: true})
			if err != nil {
				if err != pgx.ErrNoRows {
					s.Logger.Errorw("failed to get user", "error", err)
					return nil, c.SendStatus(http.StatusInternalServerError)
				}
			} else {
				return &user, nil
			}

			// Create User
			user, err = s.Queries.CreateUser(c.Context(), queries.CreateUserParams{
				Name: name, Email: email, Pic: pgtype.Text{String: pic, Valid: true}, GoogleID: pgtype.Text{String: id, Valid: true},
			})

			if err != nil {
				s.Logger.Errorw("failed to create user", "error", err)
				return nil, c.SendStatus(http.StatusInternalServerError)
			}

			return &user, nil
		}

		user, err := getUser()
		if user == nil {
			return nil
		}
		if err != nil {
			return c.SendStatus(http.StatusInternalServerError)
		}

		// Set session
		c.Cookie(&fiber.Cookie{
			Name:     "logged-in-user",
			Value:    user.ID.String(),
			Expires:  time.Now().Add(24 * time.Hour * 365),
			HTTPOnly: true,
			SameSite: "Strict",
		})

		return c.JSON(fiber.Map{"user": user})
	})

	app.Get("/state", func(c *fiber.Ctx) error {
		states, err := s.Queries.GetStates(c.Context())
		if err != nil {
			s.Logger.Errorw("failed to get states", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get states")
		}

		return c.Render("views/states", fiber.Map{"States": states})
	})

	app.Get("/state/:state", func(c *fiber.Ctx) error {
		state, err := url.QueryUnescape(c.Params("state"))
		if err != nil {
			return c.SendStatus(http.StatusBadRequest)
		}

		districts, err := s.Queries.GetDistricts(c.Context(), pgtype.Text{String: state, Valid: true})
		if err != nil {
			s.Logger.Errorw("failed to get districts", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get districts")
		}

		return c.Render("views/state", fiber.Map{"Districts": districts, "State": state})
	})

	app.Get("/state/:state/district/:district", func(c *fiber.Ctx) error {
		state, err := url.QueryUnescape(c.Params("state"))
		if err != nil {
			return c.SendStatus(http.StatusBadRequest)
		}
		district, err := url.QueryUnescape(c.Params("district"))
		if err != nil {
			return c.SendStatus(http.StatusBadRequest)
		}

		pincodes, err := s.Queries.GetPincodeByDistrict(c.Context(), queries.GetPincodeByDistrictParams{
			District:  pgtype.Text{String: district, Valid: true},
			Statename: pgtype.Text{String: state, Valid: true},
		})
		if err != nil {
			s.Logger.Errorw("failed to get pincodes", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("failed to get pincodes")
		}

		return c.Render("views/district", fiber.Map{
			"State":    state,
			"District": district,
			"Pincodes": pincodes,
		})
	})
}

func setSession(user queries.User) {
	//
}
