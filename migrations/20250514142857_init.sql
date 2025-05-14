-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS "Role" (
    id serial PRIMARY KEY,
    key character varying NOT NULL UNIQUE,
    value character varying NOT NULL
);

CREATE TABLE IF NOT EXISTS "User" (
    id serial PRIMARY KEY ,
    role_id integer NOT NULL,
    login character varying NOT NULL UNIQUE,
    name character varying NOT NULL,
    password character varying NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint,
    FOREIGN KEY (role_id) REFERENCES "Role"(id)
);

CREATE TABLE IF NOT EXISTS "Session" (
    hash character varying PRIMARY KEY,
    user_id integer NOT NULL,
    created_at bigint,
    FOREIGN KEY (user_id) REFERENCES "User"(id)
);

INSERT INTO "Role" (key, value)
VALUES
    ('admin', 'Админ'),
    ('user', 'Пользователь'),
    ('operator', 'Оператор');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS "Session";
DROP TABLE IF EXISTS "User";
DROP TABLE IF EXISTS "Role";
-- +goose StatementEnd
