package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Authentication  AuthenticationConfig `yaml:"authentication"`
	TargetServerURL string               `yaml:"targetServerURL"`
}

// AuthenticationConfig contains a list of users
type AuthenticationConfig struct {
	Users     []User `yaml:"users"`
	KeepOrgID bool   `yaml:"keepOrgId"`
}

// User Identifies a user including the tenant
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	OrgID    string `yaml:"orgid"`
}

// ParseConfig read a configuration file in the path `location` and returns a Config object
func ParseConfig(location *string) (*Config, error) {
	data, err := os.ReadFile(*location)
	if err != nil {
		return nil, err
	}
	config := Config{}
	err = yaml.Unmarshal([]byte(data), &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
