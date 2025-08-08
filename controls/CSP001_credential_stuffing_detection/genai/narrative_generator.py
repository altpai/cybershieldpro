import json

def generate_static_narrative(input_data: dict) -> dict:
    event_type = input_data.get("event_type", "unknown")
    locations = input_data.get("location", {})
    risk_score = input_data.get("risk_score", None) 

    if isinstance(locations, dict):
        locations = [locations]

    narratives = []
    localization_tags = set()

    for location in locations:
        country = location.get("country")
        city = location.get("city")
        region = location.get("region")
        org = location.get("organization")

        narrative_parts = []

        if country and country.lower() != "india":
            narrative_parts.append(
                f"Suspicious login detected from {city or 'Unknown City'}, {region or 'Unknown Region'}, {country}, which is outside the user's usual region."
            )

        if org and "VPN" in org.upper():
            narrative_parts.append("The IP belongs to a VPN provider, indicating possible location spoofing.")

        if "multiple_failed_logins" in event_type:
            narrative_parts.append("Multiple failed login attempts suggest potential brute-force activity.")

        if not narrative_parts:
            narrative_parts.append("Login event observed with no significant anomalies based on location data.")

        narratives.append(" ".join(narrative_parts))

        if country:
            localization_tags.add(country)

    full_narrative = " ".join(narratives)

    # Use provided risk_score to determine recommendation; fallback to default if none given
    if risk_score is None:
        recommendation = "No risk score provided; unable to generate recommendation."
    else:
        if risk_score >= 70:
            recommendation = "Block IP(s) and initiate password reset for the user."
        elif risk_score >= 40:
            recommendation = "Monitor account activity closely and alert the user."
        else:
            recommendation = "No action required. Continue normal monitoring."

    return {
        "narrative": full_narrative,
        "recommendation": recommendation,
        "localization_tags": list(localization_tags)
    }

def generate_narrative(input_data: dict) -> dict:
    result = generate_static_narrative(input_data)
    return result
