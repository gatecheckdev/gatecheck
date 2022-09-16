package models

import "time"

type ProductType struct {
	Id              int       `json:"id,omitempty"`
	Name            string    `json:"name,omitempty"`
	Description     string    `json:"description,omitempty"`
	CriticalProduct bool      `json:"critical_product,omitempty"`
	KeyProduct      bool      `json:"key_product,omitempty"`
	Updated         time.Time `json:"updated,omitempty"`
	Created         time.Time `json:"created,omitempty"`
	Members         []int     `json:"members,omitempty"`
}
