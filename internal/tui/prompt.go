package tui

import (
	"os"

	survey "github.com/AlecAivazis/survey/v2"
	"golang.org/x/term"
)

type Prompter interface {
	Select(label string, options []string) (string, error)
	Input(label string, defaultVal string) (string, error)
	Confirm(label string, defaultVal bool) (bool, error)
}

type surveyPrompter struct{}

func NewPrompter() Prompter {
	return &surveyPrompter{}
}

func (p *surveyPrompter) Select(label string, options []string) (string, error) {
	var result string
	prompt := &survey.Select{
		Message: label,
		Options: options,
	}
	err := survey.AskOne(prompt, &result)
	return result, err
}

func (p *surveyPrompter) Input(label string, defaultVal string) (string, error) {
	var result string
	prompt := &survey.Input{
		Message: label,
		Default: defaultVal,
	}
	err := survey.AskOne(prompt, &result)
	return result, err
}

func (p *surveyPrompter) Confirm(label string, defaultVal bool) (bool, error) {
	var result bool
	prompt := &survey.Confirm{
		Message: label,
		Default: defaultVal,
	}
	err := survey.AskOne(prompt, &result)
	return result, err
}

func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
