-- name: GetByPincode :many
SELECT * FROM pincodes
WHERE Pincode = $1;

-- name: GetPincodes :many
SELECT DISTINCT Pincode FROM pincodes
ORDER BY Pincode
LIMIT $1 OFFSET $2;

-- name: GetStates :many
SELECT DISTINCT StateName FROM pincodes
ORDER BY StateName;

-- name: GetDistricts :many
SELECT DISTINCT District FROM pincodes
WHERE StateName = $1
ORDER BY District;

-- name: GetPincodeByDistrict :many
SELECT DISTINCT Pincode FROM pincodes
WHERE District = $1 AND StateName = $2
ORDER BY Pincode;

-- name: GetPincodeVotes :one
SELECT * FROM votes_by_pincode
WHERE pincode = $1;

-- name: MostUpvoted :many
select
	pincode,
	(upvotes-downvotes) total
from
	votes_by_pincode
order by
	(upvotes-downvotes) desc
limit $1 offset $2;

-- name: MostDownvoted :many
select
	pincode,
	(upvotes-downvotes) total
from
	votes_by_pincode
order by
	(upvotes-downvotes) asc
limit $1 offset $2;

-- name: CreateUser :one
INSERT INTO users (name, email, google_id, pic) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetUserByGoogleID :one
SELECT * FROM users WHERE google_id = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetVote :one
SELECT * FROM votes WHERE pincode = $1 AND voter_id = $2;