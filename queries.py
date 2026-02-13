# queries.py

# Búsqueda general (StixDomainObjects y StixCyberObservables)
SEARCH_QUERY = """
query GlobalSearch($search: String!, $first: Int) {
  globalSearch(search: $search, first: $first) {
    edges {
      node {
        id
        entity_type
        ... on StixDomainObject {
          created_at
          name
          description
        }
        ... on StixCyberObservable {
          observable_value
          x_opencti_description
        }
      }
    }
  }
}
"""

# Obtener detalles de un Observable (IP, Hash, Domain)
GET_OBSERVABLE_QUERY = """
query GetObservable($value: String!) {
  stixCyberObservables(filters: {mode: and, filters: [{key: "value", values: [$value]}], filterGroups: []}) {
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_score
        x_opencti_description
        created_at
        indicators {
          edges {
            node {
              name
              pattern
            }
          }
        }
        reports {
          edges {
            node {
              name
              published
            }
          }
        }
      }
    }
  }
}
"""

# Obtener detalles de una Entidad (Threat Actor, Malware, etc.)
GET_ENTITY_QUERY = """
query GetEntity($name: String!) {
  stixDomainObjects(filters: {mode: and, filters: [{key: "name", values: [$name]}], filterGroups: []}) {
    edges {
      node {
        id
        entity_type
        name
        description
        created
        ... on ThreatActor {
          threat_actor_types
          goals
        }
        ... on Malware {
          malware_types
          is_family
        }
      }
    }
  }
}
"""
