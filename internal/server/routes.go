package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
	"github.com/psnehanshu/cleanpincode.in/internal/turnstile"
	"golang.org/x/sync/errgroup"
)

// Mount routes
func (s *Server) mountRoutes(router fiber.Router) {
	rootRoutes(s, router)
	authRoutes(s, router.Group("/auth"))
	pincodeRoutes(s, router.Group("/pincode"))
	voteRoutes(s, router.Group("/vote"))
	stateRoutes(s, router.Group("/state"))
	userRoutes(s, router.Group("/user"))
}

func rootRoutes(s *Server, router fiber.Router) {
	router.Get("/", func(c *fiber.Ctx) error {
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

	router.Get("/about", func(c *fiber.Ctx) error {
		return c.Render("views/about", nil)
	})

	router.Get("/contact", func(c *fiber.Ctx) error {
		return c.Render("views/contact", nil)
	})

	router.Get("/leaderboard", func(c *fiber.Ctx) error {
		mostUpvoted, err := s.queries.MostUpvoted(c.Context(), queries.MostUpvotedParams{Limit: 50})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get most upvoted pincodes")
		}

		return c.Render("views/board", fiber.Map{
			"Board": mostUpvoted, "Title": "Leaderboard", "PrizeIcon": "fa-medal",
		})
	})

	router.Get("/looserboard", func(c *fiber.Ctx) error {
		mostDownvoted, err := s.queries.MostDownvoted(c.Context(), queries.MostDownvotedParams{Limit: 50})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get MostDownvoted pincodes")
		}

		return c.Render("views/board", fiber.Map{
			"Board": mostDownvoted, "Title": "Looserboard", "PrizeIcon": "fa-skull",
		})
	})

	router.Get("/search", func(c *fiber.Ctx) error {
		searchQuery := strings.TrimSpace(c.Query("query"))
		if ues, err := url.QueryUnescape(searchQuery); err != nil {
			s.logger.Warnw("failed to unescape search term", "error", err, "query", searchQuery)
		} else {
			searchQuery = ues
		}

		if searchQuery == "" {
			return fiber.NewError(http.StatusBadRequest, "Query must not be empty")
		}

		limit := c.QueryInt("limit", 20)
		page := c.QueryInt("page", 1)
		if limit < 1 {
			limit = 1
		}
		if page < 1 {
			page = 1
		}

		results, err := s.queries.Search(c.Context(), queries.SearchParams{
			District: pgtype.Text{String: fmt.Sprintf("%%%s%%", searchQuery), Valid: true},
			Limit:    int32(limit),
			Offset:   int32((page - 1) * limit),
		})
		if err != nil {
			return err
		}

		data := fiber.Map{
			"Results": results, "Query": searchQuery,
			"Count": len(results),
			"Limit": limit, "Page": page,
			"PrevPage": page - 1, "NextPage": page + 1,
		}

		if isAjaxReq(c) {
			return c.JSON(data)
		}

		return c.Render("views/search", data)
	})
}

func authRoutes(s *Server, router fiber.Router) {
	router.Get("/login", func(c *fiber.Ctx) error {
		user := s.getRequestUser(c)
		if user != nil {
			return c.Redirect("/")
		}

		return c.Render("views/login", fiber.Map{"ClientID": os.Getenv("GOOGLE_CLIENT_ID")})
	})

	router.Post("/google-login", func(c *fiber.Ctx) error {
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

	router.Post("/logout", func(c *fiber.Ctx) error {
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

}

func pincodeRoutes(s *Server, router fiber.Router) {
	router.Get("/", func(c *fiber.Ctx) error {
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

	router.Get("/:pincode", func(c *fiber.Ctx) error {
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

		// Calculate scoreboard
		scoreboard, err := s.queries.GetPincodeScoreboard(c.Context(), pincode.Int32)
		if err != nil {
			if err == pgx.ErrNoRows {
				scoreboard.Pincode = pincode.Int32
			} else {
				return fiber.NewError(http.StatusInternalServerError, "failed to fetch scoreboard")
			}
		}

		// Fetch comments
		comments, err := s.queries.GetVoteCommentsByPincode(c.Context(), queries.GetVoteCommentsByPincodeParams{
			Pincode: pincode.Int32, Limit: 10, Offset: 0,
		})
		if err != nil {
			s.logger.Errorw("failed to fetch votes", "error", err, "pincode", pincode)
			return fiber.NewError(http.StatusInternalServerError, "failed to fetch comments")
		}

		// Fetch media
		pics, err := s.queries.GetPincodeMedia(c.Context(), queries.GetPincodeMediaParams{Pincode: pincode, Limit: 50, Offset: 0})
		if err != nil {
			s.logger.Errorw("failed to fetch Pincode pics", "error", err, "pincode", pincode.Int32)
		}

		return c.Render("views/pincode", fiber.Map{
			"PostOffices": pincodeResult,
			"Pincode":     pincode,
			"State":       strings.Join(s.getStatesForPincodes(pincodeResult), "/"),
			"Scoreboard":  scoreboard,
			"TotalVotes":  scoreboard.Upvotes - scoreboard.Downvotes,
			"Pics":        pics,
			"Comments":    comments,
			"HasComments": len(comments) > 0,
		})
	})

	router.Get("/:pincode/comments", func(c *fiber.Ctx) error {
		var pincode pgtype.Int4
		if pint, err := strconv.ParseInt(c.Params("pincode"), 10, 32); err != nil {
			return fiber.NewError(http.StatusBadRequest)
		} else {
			pincode.Int32 = int32(pint)
			pincode.Valid = true
		}

		page, limit := c.QueryInt("page", 1), c.QueryInt("limit", 50)
		if page < 1 {
			page = 1
		}
		if limit < 1 {
			limit = 1
		}
		offset := (page - 1) * limit

		pincodeResult, err := s.queries.GetByPincode(c.Context(), pincode)
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get pincode")
		}

		if len(pincodeResult) == 0 {
			return fiber.NewError(http.StatusNotFound, "pincode not found")
		}

		comments, err := s.queries.GetVoteCommentsByPincode(c.Context(), queries.GetVoteCommentsByPincodeParams{
			Pincode: pincode.Int32, Limit: int32(limit), Offset: int32(offset),
		})
		if err != nil {
			s.logger.Errorw("failed to fetch votes", "error", err, "pincode", pincode)
			return fiber.NewError(http.StatusInternalServerError, "failed to fetch comments")
		}

		return c.Render("views/comments", fiber.Map{
			"Pincode":  pincode,
			"State":    strings.Join(s.getStatesForPincodes(pincodeResult), "/"),
			"Comments": comments,
			"Limit":    limit, "Page": page, "NextPage": page + 1, "PrevPage": page - 1,
		})
	})

	router.Get("/media/:id", func(c *fiber.Ctx) error {
		var id pgtype.UUID
		if err := id.Scan(c.Params("id")); err != nil {
			return err
		}

		media, err := s.queries.GetMediaInfo(c.Context(), id)
		if err != nil {
			return err
		}

		url, err := s.s3.PresignedGetObject(c.Context(), s.bucketName, media.Link, 2*time.Minute, url.Values{})
		if err != nil {
			return err
		}

		return c.Redirect(url.String())
	})
}

func voteRoutes(s *Server, router fiber.Router) {
	cfSiteVerify := turnstile.New(os.Getenv("CF_SECRET_KEY"))

	router.Get("/", func(c *fiber.Ctx) error {
		pincode := c.QueryInt("pin")
		pincodeResult, err := s.queries.GetByPincode(c.Context(), pgtype.Int4{Int32: int32(pincode), Valid: true})
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get pincode")
		}

		if len(pincodeResult) == 0 {
			return fiber.NewError(http.StatusNotFound)
		}

		// Check logged in status
		user := s.getRequestUser(c)

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

		// Show success?
		shouldShowSuccess := c.QueryBool("show_success")

		return c.Render("views/vote", fiber.Map{
			"Pincode":     pincode,
			"Info":        pincodeResult,
			"User":        user,
			"Vote":        vote,
			"State":       strings.Join(s.getStatesForPincodes(pincodeResult), "/"),
			"showSuccess": shouldShowSuccess,
			"CfSiteKey":   os.Getenv("CF_SITE_KEY"),
		})
	})

	router.Post("/", func(c *fiber.Ctx) error {
		user := s.getRequestUser(c)
		if user == nil {
			return fiber.NewError(http.StatusUnauthorized)
		}

		// Parse the multipart form
		form, err := c.MultipartForm()
		if err != nil {
			return err
		}

		// Verify Turnstile
		{
			token := form.Value["cf-turnstile-response"]
			if len(token) < 1 {
				return fiber.NewError(http.StatusBadRequest, "CAPTCHA response token not submitted")
			}

			if err := cfSiteVerify.Verify(c.Context(), token[0]); err != nil {
				s.logger.Errorw("CAPTCHA verification failed", "error", err)
				return fiber.NewError(http.StatusForbidden, "CAPTCHA verification failed")
			}
		}

		// Extract vote type
		var voteType queries.VoteType
		{
			vt, ok := form.Value["vote_type"]
			if !ok || len(vt) == 0 || vt[0] == "" {
				return fiber.NewError(http.StatusBadRequest, "no vote type submitted")
			} else {
				switch vt[0] {
				case "upvote":
					voteType = queries.VoteTypeUp
				case "downvote":
					voteType = queries.VoteTypeDown
				default:
					return fiber.NewError(http.StatusBadRequest, fmt.Sprintf("invalid vote type: %s", vt[0]))
				}
			}
		}

		// extract pincode
		var pincode int
		{
			pincodes, ok := form.Value["pincode"]
			if !ok || len(pincodes) == 0 || pincodes[0] == "" {
				return fiber.NewError(http.StatusBadRequest, "no pincode submitted")
			} else {
				pincode, err = strconv.Atoi(pincodes[0])
				if err != nil {
					return fiber.NewError(http.StatusBadRequest, "pincode must be numeric")
				}
			}
		}

		// Fetch existing vote
		var vote *queries.Vote
		{
			v, err := s.queries.GetVote(c.Context(), queries.GetVoteParams{
				Pincode: int32(pincode), VoterID: user.ID,
			})
			if err != nil {
				if err != pgx.ErrNoRows {
					return err
				}
			} else {
				vote = &v
			}
		}

		comment := pgtype.Text{String: "", Valid: true}
		{
			c := form.Value["comment"]
			if len(c) > 0 {
				comment.String = c[0]
			}
		}

		// Record vote (with transaction)
		tx, err := s.db.Begin(c.Context())
		if err != nil {
			return err
		}
		defer tx.Rollback(c.Context())

		qtx := s.queries.WithTx(tx)

		if vote == nil {
			// new vote
			v, err := qtx.CreateVote(c.Context(), queries.CreateVoteParams{
				Type: voteType, Pincode: int32(pincode), VoterID: user.ID,
				Comment: comment,
			})
			if err != nil {
				return err
			}

			vote = &v
		} else {
			// update existing vote
			err := qtx.UpdateExistingVote(c.Context(), queries.UpdateExistingVoteParams{
				Type: voteType, ID: vote.ID, Comment: comment,
			})
			if err != nil {
				return err
			}
		}

		// Upload pics
		{
			g, ctx := errgroup.WithContext(c.Context())
			g.SetLimit(5)
			pics := form.File["pics"]
			fileNames := make([]string, 0, len(pics))
			var mu sync.Mutex

			for _, pic := range pics {
				g.Go(func() error {
					if fileName, err := s.saveFile(ctx, pic, fmt.Sprintf("vote-pics/%s", vote.ID)); err != nil {
						return err
					} else {
						mu.Lock()
						fileNames = append(fileNames, fileName)
						mu.Unlock()
					}
					return nil
				})
			}

			if err := g.Wait(); err != nil {
				return err
			}

			// Save pic info in DB
			voteIds := make([]pgtype.UUID, 0, len(fileNames))
			for i := 0; i < len(fileNames); i++ {
				voteIds = append(voteIds, vote.ID)
			}
			if err := qtx.InsertVoteFiles(c.Context(), queries.InsertVoteFilesParams{Column1: fileNames, Column2: voteIds}); err != nil {
				return err
			}
		}

		// Save vote
		if err := tx.Commit(c.Context()); err != nil {
			return err
		}

		redirectTo := fmt.Sprintf("/vote?pin=%d&show_success=true", pincode)

		if isAjaxReq(c) {
			return c.JSON(fiber.Map{"vote_id": vote.ID, "redirect": redirectTo})
		}

		return c.Redirect(redirectTo)
	})
}

func stateRoutes(s *Server, router fiber.Router) {
	router.Get("/", func(c *fiber.Ctx) error {
		states, err := s.queries.GetStates(c.Context())
		if err != nil {
			return fiber.NewError(http.StatusInternalServerError, "failed to get states")
		}

		return c.Render("views/states", fiber.Map{"States": states})
	})

	router.Get("/:state", func(c *fiber.Ctx) error {
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

	router.Get("/:state/district/:district", func(c *fiber.Ctx) error {
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

func userRoutes(s *Server, router fiber.Router) {
	router.Get("/me", func(c *fiber.Ctx) error {
		user := s.getRequestUser(c)
		if user != nil {
			return c.Redirect(fmt.Sprintf("/user/%s", user.ID.String()))
		}
		return c.Redirect("/auth/login?return=%2Fme")
	})

	router.Get("/:id", func(c *fiber.Ctx) error {
		var userUUID pgtype.UUID
		{
			userIdStr := c.Params("id")
			if userIdStr == "" {
				return fiber.NewError(http.StatusNotFound)
			}
			if err := userUUID.Scan(userIdStr); err != nil {
				return err
			}
		}

		currentUser := s.getRequestUser(c)
		var isCurrentUser bool
		if currentUser != nil {
			isCurrentUser = currentUser.ID == userUUID
		}

		user, err := s.queries.GetUserByID(c.Context(), userUUID)
		if err != nil {
			return err
		}

		return c.Render("views/user", fiber.Map{
			"IsCurrentUser": isCurrentUser, "User": user,
		})
	})
}
