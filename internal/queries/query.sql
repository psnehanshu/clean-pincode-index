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