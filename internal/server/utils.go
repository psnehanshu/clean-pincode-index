package server

import (
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/minio/minio-go/v7"
	"github.com/psnehanshu/clean-pincode-index/internal/queries"
)

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
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	jwtToken, ok := sess.Get("logged-in-user").(string)
	if !ok {
		return nil, nil
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
			return nil, nil
		}

		s.logger.Errorw("failed to get user by id", "error", err)
		return nil, fiber.NewError(http.StatusInternalServerError, "failed to get user")
	}

	return &user, nil
}

func (s *Server) handleErrors(c *fiber.Ctx, err error) error {
	// Status code defaults to 500
	code, msg := fiber.StatusInternalServerError, "Something went wrong!"

	// Retrieve the custom status code if it's a *fiber.Error
	var fErr *fiber.Error
	if errors.As(err, &fErr) {
		code = fErr.Code
		msg = fErr.Message
	} else {
		s.logger.Errorw("Error caught", "error", err)
	}

	c.Status(code)
	data := fiber.Map{"Code": code, "Message": msg}

	if isAjaxReq(c) {
		return c.JSON(data)
	}

	return c.Render("views/error", data)
}

func (s *Server) saveFile(ctx context.Context, fileH *multipart.FileHeader, location string) (string, error) {
	file, err := fileH.Open()
	if err != nil {
		return "", err
	}

	objectName := fmt.Sprintf("%s/%s__%s", location, uuid.New().String(), fileH.Filename)

	if _, err := s.s3.PutObject(ctx, s.bucketName, objectName, file, fileH.Size, minio.PutObjectOptions{}); err != nil {
		return "", err
	}

	return objectName, nil
}

// Find all unique states. In 99.99% cases, there will be only one state
func (s *Server) getStatesForPincodes(pincodes []queries.Pincode) []string {
	statesMap := make(map[string]bool)
	states := make([]string, 0, len(pincodes))

	for _, p := range pincodes {
		if statesMap[p.Statename.String] {
			continue
		}
		statesMap[p.Statename.String] = true
		states = append(states, p.Statename.String)
	}

	slices.Sort(states)
	return states
}

func generateLoginJWT(user *queries.User, expiry time.Time) (string, error) {
	claims := jwt.New()
	claims.Set(jwt.SubjectKey, user.ID.String())
	claims.Set(jwt.IssuerKey, "clean-pincode-index")
	claims.Set(jwt.AudienceKey, "clean-pincode-index")
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
		jwt.WithAudience("clean-pincode-index"),
		jwt.WithIssuer("clean-pincode-index"),
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

func (Server) getRequestUser(c *fiber.Ctx) *queries.User {
	user, ok := c.Locals("user").(*queries.User)
	if !ok {
		return nil
	}
	return user
}

func (s *Server) populateRequestUser(c *fiber.Ctx) error {
	if user, err := s.getUserFromSession(c); err != nil {
		return err
	} else {
		c.Locals("user", user)
		return nil
	}
}

func isAjaxReq(c *fiber.Ctx) bool {
	accept := strings.ToLower(string(c.Request().Header.Peek("Accept")))
	return accept == "application/json"
}
