package models

type Policy struct {

    Process string `yaml:"process"`

    Allowed []string `yaml:"allowed"`

    Deny []string `yaml:"deny"`

}
