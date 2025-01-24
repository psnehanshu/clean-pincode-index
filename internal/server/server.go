package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	pgStorage "github.com/gofiber/storage/postgres/v3"
	"github.com/gofiber/template/html/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
	"go.uber.org/zap"
)

type Server struct {
	logger       *zap.SugaredLogger
	db           *pgxpool.Pool
	queries      *queries.Queries
	sessionStore *session.Store
	close        func() error
}

func New(dbConnStr string) (*Server, error) {
	// Initialize logger
	z, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	logger := z.Sugar()

	// Initialize database
	dbPool, err := pgxpool.New(context.Background(), dbConnStr)
	if err != nil {
		return nil, err
	}

	// Initialize queries
	q := queries.New(dbPool)

	// Function supposed to be deferred
	close := func() error {
		dbPool.Close()
		return z.Sync()
	}

	// Initialize session store with Postgres
	sessionStore := session.New(session.Config{
		Storage: pgStorage.New(pgStorage.Config{DB: dbPool, Table: "__session_store"}),
	})

	// Return instance
	return &Server{logger, dbPool, q, sessionStore, close}, nil
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
		ErrorHandler:      s.handleErrors,
	})

	// Mount routes
	s.mountRoutes(app)

	// Start!
	return app.Listen(addr)
}

func (s *Server) Close() error {
	if s.close == nil {
		panic("server.clear shouldn't be nil")
	}
	return s.close()
}

// Mount routes
func (s *Server) mountRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		mostUpvoted, err := s.queries.MostUpvoted(c.Context(), queries.MostUpvotedParams{Limit: 5})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get most upvoted pincodes")
		}

		mostDownvoted, err := s.queries.MostDownvoted(c.Context(), queries.MostDownvotedParams{Limit: 5})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get most upvoted pincodes")
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
		mostUpvoted, err := s.queries.MostUpvoted(c.Context(), queries.MostUpvotedParams{Limit: 50})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get most upvoted pincodes")
		}

		return c.Render("views/board", fiber.Map{"Board": mostUpvoted, "Title": "Leaderboard"})
	})

	app.Get("/looserboard", func(c *fiber.Ctx) error {
		mostDownvoted, err := s.queries.MostDownvoted(c.Context(), queries.MostDownvotedParams{Limit: 50})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get MostDownvoted pincodes")
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

		pincodes, err := s.queries.GetPincodes(c.Context(), queries.GetPincodesParams{
			Limit: int32(limit), Offset: int32(offset),
		})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get pincodes")
		}

		return c.Render("views/pincodes", fiber.Map{
			"Pincodes": pincodes,
			"Limit":    limit, "Page": page, "NextPage": page + 1, "PrevPage": page - 1,
		})
	})

	app.Get("/pincode/:pincode", func(c *fiber.Ctx) error {
		var pincode pgtype.Int4
		if pint, err := strconv.ParseInt(c.Params("pincode"), 10, 32); err != nil {
			return fiber.NewError(http.StatusBadRequest)
		} else {
			pincode.Int32 = int32(pint)
			pincode.Valid = true
		}

		pincodeResult, err := s.queries.GetByPincode(c.Context(), pincode)
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get pincode")
		}

		if len(pincodeResult) == 0 {
			return fiber.NewError(http.StatusNotFound, "pincode not found")
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
		votes, err := s.queries.GetPincodeVotes(c.Context(), pincode.Int32)
		if err != nil {
			if err == pgx.ErrNoRows {
				votes.Pincode = pincode.Int32
			} else {
				return fiber.NewError(http.StatusInternalServerError, "failed to get pincode votes")
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
		pincode := c.QueryInt("pin")
		pincodeResult, err := s.queries.GetByPincode(c.Context(), pgtype.Int4{Int32: int32(pincode), Valid: true})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get pincode")
		}

		if len(pincodeResult) == 0 {
			return fiber.NewError(http.StatusNotFound)
		}

		// Check logged in status
		user, err := s.getUserFromSession(c)
		if err != nil {
			if fErr, ok := err.(*fiber.Error); ok {
				return fErr
			} else {
				s.logger.Warnw("failed to get user from session", "error", err)
			}
		}

		// fetch existing vote
		var vote *queries.Vote
		if user != nil {
			// fetch existing vote
			v, err := s.queries.GetVote(c.Context(), queries.GetVoteParams{
				Pincode: int32(pincode), VoterID: user.ID,
			})
			if err != nil {
				if err != pgx.ErrNoRows {
					return fiber.NewError(http.StatusInternalServerError, "failed to get vote")
				}
			} else {
				vote = &v
			}
		}

		return c.Render("views/vote", fiber.Map{
			"Pincode":  pincode,
			"Info":     pincodeResult,
			"ClientID": os.Getenv("GOOGLE_CLIENT_ID"),
			"User":     user,
			"Vote":     vote,
		})
	})

	app.Post("/vote", func(c *fiber.Ctx) error {
		return nil
	})

	app.Post("/google-login", func(c *fiber.Ctx) error {
		// Extract credential from body
		var data map[string]interface{}
		if err := json.Unmarshal(c.Body(), &data); err != nil {
			return fiber.NewError(http.StatusBadRequest, "invalid json")
		}
		credential, ok := data["credential"].(string)
		if !ok {
			return fiber.NewError(http.StatusBadRequest, "invalid json")
		}

		set, err := jwk.Fetch(c.Context(), "https://www.googleapis.com/oauth2/v3/certs")
		if err != nil {
			s.logger.Errorw("failed to fetch jwk", "error", err)
			return fiber.NewError(http.StatusInternalServerError)
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
			s.logger.Errorw("failed to parse token", "error", err)
			return fiber.NewError(http.StatusUnauthorized)
		}

		user, err := s.getUserFromGoogleJwtToken(c, token)
		if user == nil {
			return nil
		}
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError)
		}

		// Set session
		sess, err := s.sessionStore.Get(c)
		if err != nil {
			s.logger.Errorw("failed to get session", "error", err)
			return fiber.NewError(http.StatusInternalServerError)
		}

		expiryDuration := time.Hour * 24 * 365
		expiresAt := time.Now().Add(expiryDuration)
		loginToken, err := generateLoginJWT(user, expiresAt)
		if err != nil {
			s.logger.Errorw("failed to generate login token", "error", err)
			return fiber.NewError(http.StatusInternalServerError)
		}

		sess.Set("logged-in-user", loginToken)
		sess.SetExpiry(expiryDuration)

		if err := sess.Save(); err != nil {
			s.logger.Errorw("failed to save session", "error", err)
			return fiber.NewError(http.StatusInternalServerError)
		}

		return c.JSON(fiber.Map{"user": user})
	})

	app.Get("/logout", func(c *fiber.Ctx) error {
		sess, err := s.sessionStore.Get(c)
		if err != nil {
			s.logger.Errorw("failed to get session", "error", err)
			return fiber.NewError(http.StatusInternalServerError)
		}

		if err := sess.Destroy(); err != nil {
			s.logger.Errorw("failed to destroy session", "error", err)
			return fiber.NewError(http.StatusInternalServerError)
		}

		redirect := c.Query("return", "/")
		return c.Redirect(redirect)
	})

	app.Get("/state", func(c *fiber.Ctx) error {
		states, err := s.queries.GetStates(c.Context())
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get states")
		}

		return c.Render("views/states", fiber.Map{"States": states})
	})

	app.Get("/state/:state", func(c *fiber.Ctx) error {
		state, err := url.QueryUnescape(c.Params("state"))
		if err != nil {
			return fiber.NewError(http.StatusBadRequest)
		}

		districts, err := s.queries.GetDistricts(c.Context(), pgtype.Text{String: state, Valid: true})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get districts")
		}

		return c.Render("views/state", fiber.Map{"Districts": districts, "State": state})
	})

	app.Get("/state/:state/district/:district", func(c *fiber.Ctx) error {
		state, err := url.QueryUnescape(c.Params("state"))
		if err != nil {
			return fiber.NewError(http.StatusBadRequest)
		}
		district, err := url.QueryUnescape(c.Params("district"))
		if err != nil {
			return fiber.NewError(http.StatusBadRequest)
		}

		pincodes, err := s.queries.GetPincodeByDistrict(c.Context(), queries.GetPincodeByDistrictParams{
			District:  pgtype.Text{String: district, Valid: true},
			Statename: pgtype.Text{String: state, Valid: true},
		})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get pincodes")
		}

		return c.Render("views/district", fiber.Map{
			"State":    state,
			"District": district,
			"Pincodes": pincodes,
		})
	})
}

func (s *Server) getUserFromGoogleJwtToken(c *fiber.Ctx, token jwt.Token) (*queries.User, error) {
	var email, name, pic string
	id, ok := token.Subject()
	if !ok {
		s.logger.Errorw("failed to parse sub")
		return nil, fiber.NewError(http.StatusBadRequest)
	}
	if err := token.Get("email", &email); err != nil {
		s.logger.Errorw("failed to parse email", "error", err)
		return nil, fiber.NewError(http.StatusBadRequest)
	}
	if err := token.Get("name", &name); err != nil {
		s.logger.Errorw("failed to parse name", "error", err)
		return nil, fiber.NewError(http.StatusBadRequest)
	}
	if err := token.Get("picture", &pic); err != nil {
		s.logger.Errorw("failed to parse picture", "error", err)
		return nil, fiber.NewError(http.StatusBadRequest)
	}

	// Find user
	user, err := s.queries.GetUserByGoogleID(c.Context(), pgtype.Text{String: id, Valid: true})
	if err != nil {
		if err != pgx.ErrNoRows {
			s.logger.Errorw("failed to get user", "error", err)
			return nil, fiber.NewError(http.StatusInternalServerError)
		}
	} else {
		return &user, nil
	}

	// Create User
	user, err = s.queries.CreateUser(c.Context(), queries.CreateUserParams{
		Name: name, Email: email, Pic: pgtype.Text{String: pic, Valid: true}, GoogleID: pgtype.Text{String: id, Valid: true},
	})

	if err != nil {
		s.logger.Errorw("failed to create user", "error", err)
		return nil, fiber.NewError(http.StatusInternalServerError)
	}

	return &user, nil
}

func (s *Server) getUserFromSession(c *fiber.Ctx) (*queries.User, error) {
	sess, err := s.sessionStore.Get(c)
	if err != nil {
		return nil, fmt.Errorf("failed to get session")
	}

	jwtToken, ok := sess.Get("logged-in-user").(string)
	if !ok {
		return nil, fmt.Errorf("logged-in-user cookie not found")
	}

	loggedInUserId, err := getUserIdFromLoginJWT(jwtToken)
	if err != nil {
		return nil, err
	}

	var uuid pgtype.UUID
	if err := uuid.Scan(loggedInUserId); err != nil {
		return nil, err
	}

	user, err := s.queries.GetUserByID(c.Context(), uuid)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}

		s.logger.Errorw("failed to get user by id", "error", err)
		return nil, fiber.NewError(http.StatusInternalServerError, "failed to get user")
	}

	return &user, nil
}

func (s *Server) handleErrors(ctx *fiber.Ctx, err error) error {
	// Status code defaults to 500
	code, msg := fiber.StatusInternalServerError, "Something went wrong!"

	// Retrieve the custom status code if it's a *fiber.Error
	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
		msg = e.Message
	}

	return ctx.Render("views/error", fiber.Map{"Code": code, "Message": msg})
}

func generateLoginJWT(user *queries.User, expiry time.Time) (string, error) {
	claims := jwt.New()
	claims.Set(jwt.SubjectKey, user.ID.String())
	claims.Set(jwt.IssuerKey, "cleanpincode.in")
	claims.Set(jwt.AudienceKey, "cleanpincode.in")
	claims.Set(jwt.IssuedAtKey, time.Now())
	claims.Set(jwt.ExpirationKey, expiry)
	claims.Set(jwt.NotBeforeKey, time.Now())

	token, err := jwt.Sign(claims, jwt.WithKey(jwa.HS256(), []byte(os.Getenv("JWT_PRIVATE_KEY"))))
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func getUserIdFromLoginJWT(token string) (string, error) {
	t, err := jwt.Parse(
		[]byte(token),
		jwt.WithKey(jwa.HS256(), []byte(os.Getenv("JWT_PRIVATE_KEY"))),
		jwt.WithAudience("cleanpincode.in"),
		jwt.WithIssuer("cleanpincode.in"),
	)
	if err != nil {
		return "", err
	}

	if sub, ok := t.Subject(); ok {
		return sub, nil
	} else {
		return "", fmt.Errorf("subject not found")
	}
}
