CREATE ROLE sfae_app LOGIN PASSWORD 'sfae_app_password';

CREATE TABLE sfae_people (
  id integer PRIMARY KEY,
  name text NOT NULL,
  role_name text NOT NULL
);

INSERT INTO sfae_people (id, name, role_name) VALUES
  (1, 'Ada Lovelace', 'admin'),
  (2, 'Grace Hopper', 'analyst');

GRANT CONNECT ON DATABASE sfae_protocol TO sfae_app;
GRANT USAGE ON SCHEMA public TO sfae_app;
GRANT SELECT ON sfae_people TO sfae_app;
