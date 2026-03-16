from pathlib import Path
from datetime import datetime
from contextlib import redirect_stdout
import io
import os
import json
import time
import copy

from openai import OpenAI
from openai import BadRequestError, APIConnectionError, APITimeoutError, RateLimitError, InternalServerError

from .myKeys import OPENAI_API_KEY
from .syscallAiPrompts import PROMPT_PREFIX, schema


SAVE_STEM = "calls"
CURRENT_JSON_NAME = f"{SAVE_STEM}_current.json"
RESUME_CURRENT = False
AUTO_SAVE_CURRENT = True
SHOW_STRUCTURE_FIELDS_IN_TEXT = True

MODEL = "gpt-4.1"

DEBUG_OUTPUT = False
JSON_SUBDIR_NAME = "json"


MODEL_PRICING = {
	"gpt-4.1": {
		"input_per_million": 2.0,
		"output_per_million": 8.0
	},
	"gpt-4o": {
		"input_per_million": 2.5,
		"output_per_million": 10.0
	}
}


runStats = {
	"numCalls": 0,
	"promptTokens": 0,
	"completionTokens": 0,
	"totalTokens": 0,
	"estimatedCost": 0.0
}


def dprint(*args, **kwargs):
	if DEBUG_OUTPUT:
		print(*args, **kwargs)


def resetRunStats():
	runStats["numCalls"] = 0
	runStats["promptTokens"] = 0
	runStats["completionTokens"] = 0
	runStats["totalTokens"] = 0
	runStats["estimatedCost"] = 0.0


def estimateCostFromCounts(modelName: str, promptTokens: int, completionTokens: int) -> float:
	pricing = MODEL_PRICING[modelName]
	inputCost = (promptTokens / 1_000_000) * pricing["input_per_million"]
	outputCost = (completionTokens / 1_000_000) * pricing["output_per_million"]
	return inputCost + outputCost


def addUsageToRunStats(modelName: str, usageObj) -> float:
	callCost = estimateCostFromCounts(
		modelName,
		usageObj.prompt_tokens,
		usageObj.completion_tokens
	)

	runStats["numCalls"] += 1
	runStats["promptTokens"] += usageObj.prompt_tokens
	runStats["completionTokens"] += usageObj.completion_tokens
	runStats["totalTokens"] += usageObj.total_tokens
	runStats["estimatedCost"] += callCost

	return callCost


def printRunStats():
	dprint("\n--- Running Totals ---")
	dprint("OpenAI calls:", runStats["numCalls"])
	dprint("Prompt tokens:", runStats["promptTokens"])
	dprint("Completion tokens:", runStats["completionTokens"])
	dprint("Total tokens:", runStats["totalTokens"])
	dprint(f"Estimated total cost: ${runStats['estimatedCost']:.6f}")


def makeEmptyAggregate():
	return {
		"calls": [],
		"structures": {}
	}


def getWorkingDir():
	return Path.cwd()


def getJsonDir(baseDir=None):
	if baseDir is None:
		baseDir = getWorkingDir()

	baseDir = Path(baseDir)
	jsonDir = baseDir / JSON_SUBDIR_NAME
	jsonDir.mkdir(parents=True, exist_ok=True)
	return jsonDir


def getTimestamp():
	return datetime.now().strftime("%Y%m%d_%H%M%S")


def sanitizeFilenamePiece(text: str) -> str:
	if not text:
		return "noCalls"

	safeChars = []
	for ch in str(text):
		if ch.isalnum() or ch in ("-", "_"):
			safeChars.append(ch)
		else:
			safeChars.append("_")

	cleaned = "".join(safeChars).strip("_")
	return cleaned or "noCalls"


def getFirstFuncName(result: dict) -> str:
	calls = result.get("calls", [])
	if not calls:
		return "noCalls"

	firstName = calls[0].get("ntFunc", "noCalls")
	return sanitizeFilenamePiece(firstName)


def writeTextAtomic(path: Path, text: str):
	tempPath = path.with_suffix(path.suffix + ".tmp")
	tempPath.write_text(text, encoding="utf-8")
	tempPath.replace(path)


def saveJsonFile(path: Path, data: dict):
	jsonText = json.dumps(data, indent=2)
	writeTextAtomic(path, jsonText)


def loadJsonFile(path: Path):
	if not path.exists():
		return None

	raw = path.read_text(encoding="utf-8")

	if not raw or not raw.strip():
		dprint(f"Warning: JSON file is empty: {path}")
		return None

	try:
		return json.loads(raw)
	except json.JSONDecodeError as e:
		dprint(f"Warning: invalid JSON in {path}: {e}")
		return None

def convertChunkStructuresToDict(result: dict) -> dict:
	if not isinstance(result, dict):
		return {
			"calls": [],
			"structures": {}
		}

	calls = result.get("calls", [])
	if not isinstance(calls, list):
		calls = []

	structures = result.get("structures", {})
	structuresDict = {}

	# Canonical format: dict already
	if isinstance(structures, dict):
		for structId, structDef in structures.items():
			if isinstance(structDef, dict):
				structuresDict[structId] = {
					"type": structDef.get("type", "<unknown>"),
					"fields": structDef.get("fields", [])
				}

	# Legacy compatibility only: list with embedded "id"
	elif isinstance(structures, list):
		for structEntry in structures:
			if not isinstance(structEntry, dict):
				continue

			structId = structEntry.get("id")
			if not structId:
				continue

			structuresDict[structId] = {
				"type": structEntry.get("type", "<unknown>"),
				"fields": structEntry.get("fields", [])
			}

	return {
		"calls": calls,
		"structures": structuresDict
	}


def normalizeAggregate(data):
	if not isinstance(data, dict):
		return makeEmptyAggregate()

	if "calls" not in data or not isinstance(data["calls"], list):
		data["calls"] = []

	if "structures" not in data or not isinstance(data["structures"], dict):
		data["structures"] = {}

	return data


def loadCurrentAggregate(jsonDir: Path):
	currentPath = jsonDir / CURRENT_JSON_NAME
	loaded = loadJsonFile(currentPath)

	if loaded is None:
		return makeEmptyAggregate()

	return normalizeAggregate(loaded)


def saveCurrentAggregate(aggregate: dict, jsonDir: Path):
	currentPath = jsonDir / CURRENT_JSON_NAME
	saveJsonFile(currentPath, aggregate)
	return currentPath


def renderCallsNicerText(result, showStructureFields=True):
	buffer = io.StringIO()
	with redirect_stdout(buffer):
		formatCallsNicer(result, showStructureFields=showStructureFields)
	return buffer.getvalue()


def getNextStructNum(structureDict: dict) -> int:
	maxNum = 0

	for structId in structureDict.keys():
		if not isinstance(structId, str):
			continue

		if not structId.startswith("struct"):
			continue

		suffix = structId[len("struct"):]
		if suffix.isdigit():
			maxNum = max(maxNum, int(suffix))

	return maxNum + 1


def saveResultsBundle(result, baseDir=None, saveStem=SAVE_STEM, showStructureFields=True):
	"""
	Manual save function.
	Saves:
	- dated JSON snapshot into ./json
	- current working JSON into ./json
	- dated text rendering using formatCallsNicer() into ./json
	"""
	if baseDir is None:
		baseDir = getWorkingDir()

	jsonDir = getJsonDir(baseDir)
	timestamp = getTimestamp()
	firstFunc = getFirstFuncName(result)

	datedJsonPath = jsonDir / f"{saveStem}_{firstFunc}_{timestamp}.json"
	currentJsonPath = jsonDir / CURRENT_JSON_NAME
	datedTextPath = jsonDir / f"{saveStem}_{firstFunc}_{timestamp}.txt"

	saveJsonFile(datedJsonPath, result)
	saveJsonFile(currentJsonPath, result)

	prettyText = renderCallsNicerText(
		result,
		showStructureFields=showStructureFields
	)
	writeTextAtomic(datedTextPath, prettyText)

	dprint("\n--- Saved Files ---")
	dprint("Dated JSON:", datedJsonPath)
	dprint("Current JSON:", currentJsonPath)
	dprint("Dated text:", datedTextPath)

	return {
		"datedJson": datedJsonPath,
		"currentJson": currentJsonPath,
		"datedText": datedTextPath
	}


def mergeChunkResult(aggregate: dict, chunkResult: dict, chunkIndex: int) -> dict:
	"""
	Merge one chunk result into the aggregate JSON.

	Behavior:
	- preserves call order by appending
	- stores structures in a top-level dictionary keyed by struct ID
	- remaps structure IDs so there are no collisions across chunks
	- updates each push's structureRef accordingly
	- does NOT deduplicate anything
	"""

	aggregate = normalizeAggregate(aggregate)
	chunkResult = normalizeAggregate(copy.deepcopy(chunkResult))

	structureIdMap = {}
	nextStructNum = getNextStructNum(aggregate["structures"])

	for oldId, structEntry in chunkResult["structures"].items():
		newId = f"struct{nextStructNum}"
		nextStructNum += 1

		structureIdMap[oldId] = newId
		aggregate["structures"][newId] = copy.deepcopy(structEntry)

	for callEntry in chunkResult["calls"]:
		newCallEntry = copy.deepcopy(callEntry)

		for pushEntry in newCallEntry.get("pushes", []):
			oldRef = pushEntry.get("structureRef")
			if oldRef:
				pushEntry["structureRef"] = structureIdMap.get(oldRef, oldRef)

		aggregate["calls"].append(newCallEntry)

	return aggregate


def formatField(field, nameWidth=24, typeWidth=20):
	fieldName = field.get("fieldName", "<unknown>")
	fieldType = field.get("fieldType", "<unknown>")
	fieldValue = field.get("fieldValue", "<unknown>")
	fieldComment = field.get("fieldComment") or ""

	line = f"\t\t{fieldName:<{nameWidth}} {fieldType:<{typeWidth}} = {fieldValue}"
	if fieldComment:
		line += f"    ; {fieldComment}"
	return line


def formatStructure(structId, structDef):
	if not structDef:
		return

	structType = structDef.get("type", "<unknown>")
	fields = structDef.get("fields", [])

	print(f"\tstructure definition: {structType} ({structId})")
	if not fields:
		print("\t\t<no fields>")
		return

	for field in fields:
		print(formatField(field))


def formatPushEntry(entry, structureMap=None, commentColumn=24, showStructureFields=True):
	value = entry.get("value", "<unknown>")
	comment = entry.get("additionalComment") or ""
	structurePointer = entry.get("structurePointer")
	structureRef = entry.get("structureRef")
	structureValueExpectations = entry.get("structureValueExpectations")
	pointedValue = entry.get("pointedValue")

	line = f"push {value}"
	if comment:
		padding = max(1, commentColumn - len(value))
		line += (" " * padding) + f"; {comment}"
	print(line)

	if pointedValue:
		print(f"\tpointed value: {pointedValue}")

	if structurePointer:
		if structureRef:
			print(f"\tstructure: {structurePointer} ({structureRef})")
		else:
			print(f"\tstructure: {structurePointer}")

	if structureValueExpectations:
		print(f"\texpected fields: {structureValueExpectations}")

	if structureRef and structureMap:
		structDef = structureMap.get(structureRef)
		if structDef and showStructureFields:
			formatStructure(structureRef, structDef)
		elif showStructureFields:
			print(f"\tstructure definition: <missing for {structureRef}>")

	print()


def formatPushes(pushes, structureMap=None, commentColumn=24, showStructureFields=True):
	for entry in pushes:
		formatPushEntry(
			entry,
			structureMap=structureMap,
			commentColumn=commentColumn,
			showStructureFields=showStructureFields
		)


def formatPushesNicer(pushes, structureMap=None, showStructureFields=True):
	formatPushes(
		pushes,
		structureMap=structureMap,
		commentColumn=24,
		showStructureFields=showStructureFields
	)


def formatCalls(result, showStructureFields=True):
	calls = result.get("calls", [])
	structureMap = result.get("structures", {})

	for idx, call in enumerate(calls, start=1):
		ntFunc = call.get("ntFunc", "<unknown>")
		pushes = call.get("pushes", [])

		print(f"=== Call {idx}: {ntFunc} ===")
		formatPushes(
			pushes,
			structureMap=structureMap,
			commentColumn=24,
			showStructureFields=showStructureFields
		)


def formatCallsNicer(result, showStructureFields=True):
	formatCalls(result, showStructureFields=showStructureFields)


def runPrompt(myPrompt: str):
	client = OpenAI(api_key=OPENAI_API_KEY)

	response = client.chat.completions.create(
		model=MODEL,
		messages=[{"role": "user", "content": myPrompt}],
		response_format={
			"type": "json_schema",
			"json_schema": schema
		},
		temperature=0
	)

	raw = response.choices[0].message.content
	usage = response.usage

	callCost = addUsageToRunStats(MODEL, usage)

	dprint("\n--- Token Usage For This Call ---")
	dprint("Prompt tokens:", usage.prompt_tokens)
	dprint("Completion tokens:", usage.completion_tokens)
	dprint("Total tokens:", usage.total_tokens)
	dprint(f"Estimated cost for this call: ${callCost:.6f}")

	parsed = json.loads(raw)

	# json.loads() already converts JSON null -> Python None in memory.
	# This additionally converts structures from list form into dict form in memory.
	parsed = convertChunkStructuresToDict(parsed)
	return parsed


def runPromptWithRetry(myPrompt: str, maxRetries=5, baseDelay=3):
	attempt = 0

	while True:
		try:
			return runPrompt(myPrompt)

		except KeyboardInterrupt:
			raise

		except BadRequestError:
			raise

		except (APIConnectionError, APITimeoutError, RateLimitError, InternalServerError) as e:
			attempt += 1
			if attempt > maxRetries:
				dprint(f"Giving up after {maxRetries} retries: {e}")
				raise

			delay = baseDelay * (2 ** (attempt - 1))
			dprint(f"Retryable OpenAI error on attempt {attempt}/{maxRetries}: {e}")
			dprint(f"Sleeping {delay} seconds before retry...")
			time.sleep(delay)

		except Exception as e:
			attempt += 1
			if attempt > maxRetries:
				dprint(f"Giving up after {maxRetries} retries: {e}")
				raise

			delay = baseDelay * (2 ** (attempt - 1))
			dprint(f"Unexpected error on attempt {attempt}/{maxRetries}: {e}")
			dprint(f"Sleeping {delay} seconds before retry...")
			time.sleep(delay)


def chunkList(items, chunkSize):
	for i in range(0, len(items), chunkSize):
		yield items[i:i + chunkSize]


def buildChunkPrompt(promptPrefix: str, apiChunk: list[str]) -> str:
	return promptPrefix.rstrip() + "\n\n" + "\n\n".join(apiChunk)


def processApiBlocksInChunks(
	apiBlocks: list[str],
	chunkSize: int,
	promptPrefix: str = PROMPT_PREFIX,
	resumeCurrent: bool = RESUME_CURRENT,
	autoSaveCurrent: bool = AUTO_SAVE_CURRENT,
	baseDir=None,
	debugOutput: bool = DEBUG_OUTPUT
):
	global DEBUG_OUTPUT
	DEBUG_OUTPUT = debugOutput

	if baseDir is None:
		baseDir = getWorkingDir()

	baseDir = Path(baseDir)
	baseDir.mkdir(parents=True, exist_ok=True)
	jsonDir = getJsonDir(baseDir)

	if resumeCurrent:
		aggregate = loadCurrentAggregate(jsonDir)
		dprint(f"\n--- Resuming from existing current JSON: {jsonDir / CURRENT_JSON_NAME} ---\n")
	else:
		aggregate = makeEmptyAggregate()
		dprint(f"\n--- Starting fresh; current JSON will be overwritten: {jsonDir / CURRENT_JSON_NAME} ---\n")
		if autoSaveCurrent:
			saveCurrentAggregate(aggregate, jsonDir)

	for chunkIndex, apiChunk in enumerate(chunkList(apiBlocks, chunkSize), start=1):
		chunkPrompt = buildChunkPrompt(promptPrefix, apiChunk)

		dprint(f"\n=== Processing chunk {chunkIndex} with {len(apiChunk)} API block(s) ===\n")

		chunkResult = runPromptWithRetry(chunkPrompt)

		aggregate = mergeChunkResult(
			aggregate=aggregate,
			chunkResult=chunkResult,
			chunkIndex=chunkIndex
		)

		if autoSaveCurrent:
			currentPath = saveCurrentAggregate(aggregate, jsonDir)
			dprint(f"Updated current JSON: {currentPath}")

	return aggregate


def buildPossibleValues(
	apiBlocks: list[str],
	chunkSize: int = 1,
	resumeCurrent: bool = RESUME_CURRENT,
	autoSaveCurrent: bool = AUTO_SAVE_CURRENT,
	baseDir=None,
	debugOutput: bool = DEBUG_OUTPUT
):
	resetRunStats()

	result = processApiBlocksInChunks(
		apiBlocks=apiBlocks,
		chunkSize=chunkSize,
		promptPrefix=PROMPT_PREFIX,
		resumeCurrent=resumeCurrent,
		autoSaveCurrent=autoSaveCurrent,
		baseDir=baseDir,
		debugOutput=debugOutput
	)

	return result


# if __name__ == "__main__":
# 	# from printApiBlocks import api_blocks

# 	# result = buildPossibleValues(
# 	# 	apiBlocks=api_blocks,
# 	# 	chunkSize=1,
# 	# 	resumeCurrent=False,
# 	# 	autoSaveCurrent=True,
# 	# 	baseDir=Path.cwd(),
# 	# 	debugOutput=True
# 	# )

# 	dprint("\n--- Pretty JSON (entire result) ---\n")
# 	dprint(json.dumps(result, indent=2))

# 	dprint("\n--- Pretty JSON (calls only) ---\n")
# 	dprint(json.dumps(result["calls"], indent=2))

# 	dprint("\n--- Assembly Style ---\n")
# 	if DEBUG_OUTPUT:
# 		formatCalls(result)

# 	dprint("\n--- Assembly Style 2 ---\n")
# 	if DEBUG_OUTPUT:
# 		formatCallsNicer(result)

# 	printRunStats()

# 	saveResultsBundle(
# 		result,
# 		baseDir=Path.cwd(),
# 		saveStem=SAVE_STEM,
# 		showStructureFields=SHOW_STRUCTURE_FIELDS_IN_TEXT
# 	)