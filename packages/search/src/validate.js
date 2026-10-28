/**
 * Validate a document against a strict template mapping (offline).
 *
 * @param {object} doc
 * @param {object} mapping
 * @returns {{ ok: boolean, errors: Array<string> }}
 */
export function validateDocument(doc, mapping) {
  const errors = [];
  function checkValue(value, field, path) {
    if (!field) {
      errors.push(`unknown field ${path}`);
      return;
    }
    if (field.type === "flattened") return;
    if (field.properties) {
      if (value === null || value === undefined) return;
      if (typeof value !== "object") {
        errors.push(`field ${path} should be an object`);
        return;
      }
      const items = Array.isArray(value) ? value : [value];
      for (const item of items) {
        if (item === null) continue;
        for (const key of Object.keys(item)) {
          if (!field.properties[key]) {
            errors.push(`unknown field ${path}.${key}`);
          } else {
            checkValue(item[key], field.properties[key], `${path}.${key}`);
          }
        }
      }
      return;
    }
    if (field.type === "object" && !field.properties) {
      if (value === null || value === undefined) return;
      if (typeof value !== "object") {
        errors.push(`field ${path} should be an object`);
        return;
      }
      const items = Array.isArray(value) ? value : [value];
      for (const item of items) {
        if (item === null) continue;
        for (const key of Object.keys(item)) {
          errors.push(`unknown field ${path}.${key}`);
        }
      }
      return;
    }
    const values = Array.isArray(value) ? value : [value];
    for (const v of values) {
      if (v === null || v === undefined) continue;
      if (field.type === "keyword") {
        if (typeof v !== "string") errors.push(`field ${path} should be a string`);
        else if (Buffer.byteLength(v, "utf8") > 32766) errors.push(`field ${path} exceeds keyword length`);
      } else if (field.type === "integer") {
        if (!Number.isInteger(v)) errors.push(`field ${path} should be an integer`);
      } else if (field.type === "float") {
        if (typeof v !== "number") errors.push(`field ${path} should be a number`);
      } else if (field.type === "boolean") {
        if (typeof v !== "boolean") errors.push(`field ${path} should be a boolean`);
      } else if (field.type === "date") {
        if (typeof v !== "string" || Number.isNaN(Date.parse(v))) errors.push(`field ${path} should be a date`);
      } else if (field.type === "ip") {
        if (typeof v !== "string" || !/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && !v.includes(":")) errors.push(`field ${path} should be an ip`);
      } else if (field.type === "geo_point") {
        if (typeof v !== "object" || typeof v.lat !== "number" || typeof v.lon !== "number") errors.push(`field ${path} should be a geo_point`);
      }
    }
  }
  const properties = mapping && mapping.properties ? mapping.properties : {};
  for (const key of Object.keys(doc || {})) {
    checkValue(doc[key], properties[key], key);
  }
  return { ok: errors.length === 0, errors };
}
