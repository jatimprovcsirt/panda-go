package masking

import "strings"

type MaskingConfig struct {
	KeepLeading  int
	KeepTrailing int
	MaskChar     rune
}

func Mask(plaintext string, config ...MaskingConfig) string {
	keepLeading := 2
	keepTrailing := 2
	maskChar := '*'

	if len(config) > 0 {
		if config[0].KeepLeading != 0 {
			keepLeading = config[0].KeepLeading
		}
		if config[0].KeepTrailing != 0 {
			keepTrailing = config[0].KeepTrailing
		}
		if config[0].MaskChar != 0 {
			maskChar = config[0].MaskChar
		}
	}

	runes := []rune(plaintext)
	length := len(runes)

	if length <= (keepLeading + keepTrailing) {
		return strings.Repeat(string(maskChar), length)
	}

	leading := string(runes[:keepLeading])
	trailing := string(runes[length-keepTrailing:])
	middleCount := length - keepLeading - keepTrailing
	middle := strings.Repeat(string(maskChar), middleCount)

	return leading + middle + trailing;
}
