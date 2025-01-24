package server

import (
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/psnehanshu/cleanpincode.in/internal/queries"
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

	return c.Render("views/error", fiber.Map{"Code": code, "Message": msg})
}

func (s *Server) uploadPicsForVote([]*multipart.FileHeader, pgtype.UUID) error {
	s.logger.Warn("uploadPicsForVote hasn't been implemented yet")
	return nil
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
