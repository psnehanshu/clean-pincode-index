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
