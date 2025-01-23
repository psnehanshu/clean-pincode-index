-- name: GetByPincode :many
SELECT * FROM pincodes
WHERE Pincode = $1;

-- name: GetPincodes :many
SELECT DISTINCT Pincode FROM pincodes
ORDER BY Pincode
LIMIT $1 OFFSET $2;
