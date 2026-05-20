package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

func guyGfshfResult(digestWorker *DigestWorker, result []string) {
	digestWorker.Start()

	// Step 1: Hash the bundle classes
	digestWorker.Hash([]byte(_bundle_classes))

	// Step 2: Hash the bundle identifier and version
	bundleIdentifierVersion := "<AppPackageName><AppVersion>"
	bundleIdentifierVersionData := []byte(bundleIdentifierVersion)
	digestWorker.Hash(bundleIdentifierVersionData)

	// Step 3: Hash an empty string
	emptyStringData := []byte("")
	digestWorker.Hash(emptyStringData)

	endResult := digestWorker.End()

	for i := 0; i < digestWorker.numberOfSalts; i++ {
		saltObject := endResult[i]
		base64String := base64.StdEncoding.EncodeToString(saltObject)
		result[i] = base64String
	}
}

func calculateOperation(salts []string, numberOfSalts int, result []string) {
	digestWorker := NewDigestWorker(salts, numberOfSalts)
	guyGfshfResult(digestWorker, result)
}

func createOperationsList(a1 string, a2 int) []string {
	var operationsList []string
	seed := a1
	for {
		i := 0
		ptr := []rune(seed)
		length := len(seed)

		if length <= 0 {
			break
		}

		// Find the next non-digit character
		for i < length && '0' <= ptr[i] && ptr[i] <= '9' {
			i++
		}

		if i >= length {
			break
		}

		ch := ptr[i]

		// Handle special characters
		if 'D' <= ch && ch <= 'G' {
			if i < length && int(ch) == a2 {
				newOp := seed[:i]
				operationsList = append(operationsList, newOp)
			}
		}
		seed = seed[i+1:]
	}

	return operationsList
}

func getDynamicOperationsResults(challenge string, a2 int, a3 func([]string, int, []string)) []map[string]string {
	operationsList := createOperationsList(challenge, a2)
	if len(operationsList) == 0 {
		return nil
	}

	listSize := len(operationsList)
	operationsArray := make([]string, listSize)
	resultsArray := make([]string, listSize)

	results := make([]map[string]string, listSize)
	for index, op := range operationsList {
		operationsArray[index] = op
		resultsArray[index] = op // Assuming result is stored in the same operation for now
	}

	a3(operationsArray, listSize, resultsArray)

	for i, code := range operationsList {
		results[i] = map[string]string{
			"code": code,
			"hash": resultsArray[i],
		}
	}

	return results
}

func handleDynamicOperation2(challenge string, dynamicOperationsResults []map[string]string) (string, int) {
	index := 0
	length := 0
	result := ""

	// Calculate the length of the numeric prefix of s1
	for index < len(challenge) && '0' <= challenge[index] && challenge[index] <= '9' {
		index++
		length++
	}
	index++

	if len(dynamicOperationsResults) > 0 {
		nodeIter := dynamicOperationsResults
		currentNode := nodeIter[0]
		currentNodeLength := len(currentNode["code"])
		for challenge[:length] != currentNode["code"][:currentNodeLength] {
			nodeIter = nodeIter[1:]
			if len(nodeIter) == 0 {
				return "", index
			}
			currentNode = nodeIter[0]
			currentNodeLength = len(currentNode["code"])
		}

		// Copy the string from the matching node to a3
		result = currentNode["hash"]
	}

	return result, index
}

func handleX(src string) (string, int) {
	index := 0
	for index < len(src) && '0' <= src[index] && src[index] <= '9' {
		index++
	}

	dst := src[:index]
	return dst, index + 1
}

func nq2382(a1, s string) (string, int) {
	strLen := len(s)
	index1 := (10*int(a1[1]) + 100*int(a1[0]) + int(a1[2]) - 5328) % strLen
	index2 := (10*int(a1[4]) + 100*int(a1[3]) + int(a1[5]) - 5328) % strLen
	startIndex := min(index1, index2)
	endIndex := max(index1, index2)

	a3 := s[startIndex : endIndex+1]
	return a3, 7
}

func sha256Base64(data []byte) string {
	hash := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func parse(challenge, bundleIdentifierHash, bundleVersionHash string) string {
	if challenge == "" {
		return "Error"
	}

	dynamicOperationsResult70 := getDynamicOperationsResults(challenge, 70, calculateOperation)
	dynamicOperationsResult68 := getDynamicOperationsResults(challenge, 68, calculateOperation)
	buffer := make([]string, 5)
	var result []string

	for challenge != "" {
		challengePtr := strings.NewReader(challenge)
		code, _, err := challengePtr.ReadRune()
		if err != nil {
			break
		}
		for '0' <= code && code <= '9' {
			code, _, err = challengePtr.ReadRune()
			if err != nil {
				break
			}
		}

		if code == 'D' || code == 'F' {
			index := -1
			buffer[2], _ = nq2382(challenge, bundleIdentifierHash)
			buffer[3], _ = nq2382(challenge, bundleVersionHash)
			buffer[1], index = handleDynamicOperation2(
				challenge, dynamicOperationsResult68)
			if code == 'F' {
				buffer[1], index = handleDynamicOperation2(challenge, dynamicOperationsResult70)
			}
			challenge = challenge[index:]
		} else if code == 'E' || code == 'G' {
			buffer[2], _ = nq2382(challenge, bundleIdentifierHash)
			buffer[3], _ = nq2382(challenge, bundleVersionHash)
			for '0' <= challenge[0] && challenge[0] <= '9' {
				challenge = challenge[1:]
			}
		} else if code == 'X' {
			index := -1
			buffer[0], index = handleX(challenge)
			challenge = challenge[index:]
		} else {
			return "Error"
		}

		buffer[4] += buffer[3] + buffer[2] + buffer[1] + buffer[0] + "|"
		result = append(result, buffer[4])
		buffer = make([]string, 5)
	}

	resultStr := strings.Join(result, "")
	return resultStr[:len(resultStr)-1] // Remove the last '|'
}

func resolveChallenge(challenge string) string {
	return sha256Base64([]byte(parse(
		challenge,
		sha256Base64([]byte("<AppPackageName>")),
		sha256Base64([]byte("<AppVersion>")),
	)))
}

var _bundle_classes string = "<ALL_BUNDLE_CLASSNAMES_CONCATENATED>"
