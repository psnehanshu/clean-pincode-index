CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE pincodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    CircleName VARCHAR(50),
    RegionName VARCHAR(50),
    DivisionName VARCHAR(50),
    OfficeName VARCHAR(50),
    Pincode INTEGER,
    OfficeType VARCHAR(50),
    Delivery VARCHAR(50),
    District VARCHAR(50),
    StateName VARCHAR(50),
    Country TEXT DEFAULT 'India'
);
CREATE INDEX pincodes_Pincode_IDX ON pincodes (Pincode);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    google_id TEXT UNIQUE,
    pic TEXT,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TYPE vote_type AS ENUM ('up', 'down');
CREATE TABLE votes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type vote_type NOT NULL,
    pincode INTEGER NOT NULL,
    voter_id UUID NOT NULL,
    comment TEXT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX votes_type_idx ON votes (type);
ALTER TABLE votes
ADD CONSTRAINT votes_users_fk
FOREIGN KEY (voter_id) REFERENCES users(id);
ALTER TABLE votes ADD CONSTRAINT votes_user_pincode_uk UNIQUE (pincode,voter_id);

CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$
 language 'plpgsql';

CREATE TRIGGER update_votes_modtime
BEFORE UPDATE ON votes
FOR EACH ROW
EXECUTE FUNCTION update_modified_column();



CREATE TABLE vote_pics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    link TEXT NOT NULL,
    vote_id UUID NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE vote_pics
ADD CONSTRAINT votes_pics_fk
FOREIGN KEY (vote_id) REFERENCES votes(id);

CREATE OR REPLACE VIEW votes_by_pincode
AS SELECT pincode,
    count(
        CASE
            WHEN type = 'up'::vote_type THEN 1
            ELSE NULL::integer
        END) AS upvotes,
    count(
        CASE
            WHEN type = 'down'::vote_type THEN 1
            ELSE NULL::integer
        END) AS downvotes
   FROM votes v
  GROUP BY pincode
  ORDER BY pincode;