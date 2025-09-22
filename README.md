## Welcome y welcome

### Series (Parent with Sub-posts)

Group related posts under a parent so the index shows just the parent and the parent page lists all children as cards.

Parent post example:

```md
---
title: "My App – Overview"
published: 2025-09-22
series:
  id: "my-app-series"
  name: "My App Challenges"
  parent: true
---
```

Child post example:

```md
---
title: "Challenge 01"
published: 2025-09-22
series:
  id: "my-app-series"
  order: 1
---
```

Notes:

- Children are hidden from the main lists; they render on the parent page under the series section.
- `order` controls child ordering when present; otherwise children are sorted by `published` date.
