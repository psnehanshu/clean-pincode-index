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
    username VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TYPE vote_type AS ENUM ('up', 'down');
CREATE TABLE votes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type vote_type NOT NULL,
    pincode INTEGER NOT NULL,
    voter_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX votes_type_idx ON votes (type);
ALTER TABLE votes
ADD CONSTRAINT votes_users_fk
FOREIGN KEY (voter_id) REFERENCES users(id);

CREATE TABLE vote_pics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    link TEXT NOT NULL,
    vote_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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