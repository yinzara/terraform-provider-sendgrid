package sendgrid

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidImportFormat error displayed when the string passed to import a template version
	// doesn't have the good format.
	ErrInvalidImportFormat = errors.New("invalid import. Supported import format: {{templateID}}/{{templateVersionID}}")

	// ErrSubUserNotFound error displayed when the subUser can not be found.
	ErrSubUserNotFound = errors.New("subUser wasn't found")

	// ErrNoNewVersionFoundForTemplate error displayed when no recent version can be found for a given template.
	ErrNoNewVersionFoundForTemplate = errors.New("no recent version found for template_id")
)

func subUserNotFound(name string) error {
	return fmt.Errorf("%w: %s", ErrSubUserNotFound, name)
}
