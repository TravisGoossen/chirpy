-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: Login :one
SELECT * FROM users
WHERE email = $1;

-- name: UpdateEmailPassword :exec
UPDATE users
SET email = $2, hashed_password = $3, updated_at = NOW()
WHERE id = $1;

-- name: GetUserInfo :one
SELECT id, created_at, updated_at, email, is_chirpy_red
FROM users
WHERE id = $1;


-- name: UpgradeUserRed :one
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1
RETURNING id;