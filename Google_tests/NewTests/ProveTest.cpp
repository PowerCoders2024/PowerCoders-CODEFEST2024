//
// Created by danny on 8/2/24.
//
#include "gtest/gtest.h"
#include "../../EarthClient/EarthBase.h"

// Tests para EarthBase
class EarthBaseTest : public ::testing::Test {
protected:
    EarthBase earthBase;
    Satellite satellite;

    void SetUp() override {
        // Inicializar la base terrestre y el satélite
        earthBase.initializeEarthBase();
        satellite.initializeSatellite();
    }
};

TEST_F(EarthBaseTest, ReceiveServerHintRecognized) {

    unsigned int result = earthBase.receiveServerHint(satellite);
    EXPECT_EQ(result, sizeof(earthBase.pskKey));
}

TEST_F(EarthBaseTest, ReceiveServerHintUnrecognized) {
    // Simulamos que el hint del servidor es "unknown_identity"
    const char* unexpectedHint = "unknown_identity";
    satellite.serverHint = unexpectedHint;
    unsigned int result = earthBase.receiveServerHint(satellite);
    EXPECT_EQ(result, sizeof(earthBase.pskKey));
}

// Tests para Satellite
class SatelliteTest : public ::testing::Test {
protected:
    EarthBase earthBase;
    Satellite satellite;

    void SetUp() override {
        // Inicializar el satélite
        earthBase.initializeEarthBase();
        satellite.initializeSatellite();
    }
};

TEST_F(SatelliteTest, VerifyClientIdentityRecognized) {
    unsigned int result = satellite.verifyClientIdentity(nullptr, earthBase.client_identity);
    EXPECT_EQ(result, sizeof(satellite.pskKey));
}

TEST_F(SatelliteTest, VerifyClientIdentityUnrecognized) {
    unsigned int result = satellite.verifyClientIdentity(nullptr, "unkonwn");
    EXPECT_EQ(result, 0);
}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    return    RUN_ALL_TESTS();;
}