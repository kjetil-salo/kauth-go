-- name: GetServiceByID :one
SELECT * FROM services WHERE id = ? AND active = 1 LIMIT 1;

-- name: GetServiceByAuthHost :one
SELECT * FROM services WHERE auth_host = ? AND active = 1 LIMIT 1;

-- name: GetDefaultService :one
SELECT * FROM services WHERE is_default = 1 AND active = 1 LIMIT 1;

-- name: ListActiveServices :many
SELECT * FROM services WHERE active = 1 ORDER BY display_name;

-- name: ListAllServices :many
SELECT * FROM services ORDER BY display_name;

-- name: CreateService :exec
INSERT INTO services (id, display_name, tagline, domain, auth_host, callback_url,
    logo_html, bg_image, bg_css, theme, accent_color, email_from_name, email_from_address,
    auto_register, default_role, default_org, require_role, enforce_org, is_default,
    auth_google, auth_microsoft, auth_magic_link, auth_password,
    google_client_id, google_client_secret, microsoft_client_id, microsoft_client_secret,
    jwt_cookie_name, access_token_ttl, refresh_token_max_age, active, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: UpdateService :exec
UPDATE services SET
    display_name = ?, tagline = ?, domain = ?, auth_host = ?, callback_url = ?,
    logo_html = ?, bg_image = ?, bg_css = ?, theme = ?, accent_color = ?,
    email_from_name = ?, email_from_address = ?, auto_register = ?, default_role = ?, default_org = ?,
    require_role = ?, enforce_org = ?, is_default = ?,
    auth_google = ?, auth_microsoft = ?, auth_magic_link = ?, auth_password = ?,
    google_client_id = ?, google_client_secret = ?,
    microsoft_client_id = ?, microsoft_client_secret = ?,
    jwt_cookie_name = ?, access_token_ttl = ?, refresh_token_max_age = ?,
    active = ?, updated_at = ?
WHERE id = ?;
