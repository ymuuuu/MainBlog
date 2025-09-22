import { defineCollection, z } from 'astro:content'

// Schema for the "posts" collection
const postsCollection = defineCollection({
  schema: z.object({
    title: z.string(),
    published: z.date(),
    updated: z.date().optional(),
    draft: z.boolean().optional().default(false),
    description: z.string().optional().default(''),
    image: z.string().optional().default(''),
    tags: z.array(z.string()).optional().default([]),
    category: z.string().optional().default(''),
    lang: z.string().optional().default(''),

    // Optional series metadata for grouping related posts under a parent
    // Usage in frontmatter:
    // series:
    //   id: "app-xyz"
    //   name: "App XYZ Challenges"   # optional, shown on parent page
    //   parent: true                  # set only on the parent post
    //   order: 1                      # optional, set on child posts for ordering
    series: z
      .object({
        id: z.string(),
        name: z.string().optional(),
        parent: z.boolean().optional().default(false),
        order: z.number().optional(),
      })
      .optional(),

    /* For internal use */
    prevTitle: z.string().default(''),
    prevSlug: z.string().default(''),
    nextTitle: z.string().default(''),
    nextSlug: z.string().default(''),
  }),
})

// Schema for the "writeups" collection
const writeupsCollection = defineCollection({
  schema: z.object({
    title: z.string(),
    published: z.date(),
    updated: z.date().optional(),
    draft: z.boolean().optional().default(false),
    description: z.string().optional().default(''),
    image: z.string().optional().default(''),
    tags: z.array(z.string()).optional().default([]),
    category: z.string().optional().default(''),
    lang: z.string().optional().default(''),

    // Optional series metadata for grouping related writeups under a parent
    series: z
      .object({
        id: z.string(),
        name: z.string().optional(),
        parent: z.boolean().optional().default(false),
        order: z.number().optional(),
      })
      .optional(),

    /* For internal use */
    prevTitle: z.string().default(''),
    prevSlug: z.string().default(''),
    nextTitle: z.string().default(''),
    nextSlug: z.string().default(''),
  }),
})

// Export collections
export const collections = {
  posts: postsCollection,
  writeups: writeupsCollection,
}
