import { getCollection } from 'astro:content'
import type { BlogPostData } from '@/types/config'
import I18nKey from '@i18n/i18nKey'
import { i18n } from '@i18n/translation'

/**
 * Fetches and sorts entries from a specified collection by published date (newest first).
 * Also sets `nextSlug`, `nextTitle`, `prevSlug`, and `prevTitle` for navigation.
 */
export async function getSortedEntries(
  collectionName: 'posts' | 'writeups',
): Promise<{ body: string; data: BlogPostData; slug: string; collection: 'posts' | 'writeups' }[]> {
  const allEntries = (await getCollection(collectionName, ({ data }) => {
    return import.meta.env.PROD ? data.draft !== true : true
  })) as unknown as { body: string; data: BlogPostData; slug: string }[]

  // Add the `collection` field to each entry
  const entriesWithCollection = allEntries.map((entry) => ({
    ...entry,
    collection: collectionName,
  }))

  // Sort entries by published date (newest first)
  const sorted = entriesWithCollection.sort((a, b) => {
    const dateA = new Date(a.data.published)
    const dateB = new Date(b.data.published)
    return dateA > dateB ? -1 : 1
  })

  // Set next and previous slugs/titles for navigation
  for (let i = 1; i < sorted.length; i++) {
    sorted[i].data.nextSlug = sorted[i - 1].slug
    sorted[i].data.nextTitle = sorted[i - 1].data.title
  }

  for (let i = 0; i < sorted.length - 1; i++) {
    sorted[i].data.prevSlug = sorted[i + 1].slug
    sorted[i].data.prevTitle = sorted[i + 1].data.title
  }

  return sorted
}

/**
 * Fetches and sorts entries from the "posts" collection by published date (newest first).
 * Also sets `nextSlug`, `nextTitle`, `prevSlug`, and `prevTitle` for navigation.
 */
export async function getSortedPosts(): Promise<
  { body: string; data: BlogPostData; slug: string; collection: 'posts' | 'writeups' }[]
> {
  const entries = await getSortedEntries('posts')
  // Exclude child posts that belong to a series but are not designated as parent
  return entries.filter(e => !(e.data.series && e.data.series.parent !== true))
}

/**
 * Fetches and sorts entries from both "posts" and "writeups" collections by published date (newest first).
 * Also sets `nextSlug`, `nextTitle`, `prevSlug`, and `prevTitle` for navigation.
 */
export async function getAllSortedPosts(): Promise<
  { body: string; data: BlogPostData; slug: string; collection: 'posts' | 'writeups' }[]
> {
  const blogPosts = await getSortedEntries('posts') // Fetch posts
  const writeups = await getSortedEntries('writeups') // Fetch writeups
  const allPosts = [...blogPosts, ...writeups]

  // Sort all posts by published date (newest first)
  return allPosts.sort((a, b) => {
    const dateA = new Date(a.data.published)
    const dateB = new Date(b.data.published)
    return dateA > dateB ? -1 : 1
  })
}

/**
 * Gets a list of tags and their counts from the "posts" and "writeups" collections.
 */
export async function getTagList(): Promise<Tag[]> {
  const blogPosts = await getCollection('posts', ({ data }) => {
    return import.meta.env.PROD ? data.draft !== true : true
  })

  const writeups = await getCollection('writeups', ({ data }) => {
    return import.meta.env.PROD ? data.draft !== true : true
  })

  const allPosts = [...blogPosts, ...writeups]

  const countMap: { [key: string]: number } = {}
  allPosts.map(post => {
    post.data.tags?.map(tag => {
      if (!countMap[tag]) countMap[tag] = 0
      countMap[tag]++
    })
  })

  const keys: string[] = Object.keys(countMap).sort((a, b) => {
    return a.toLowerCase().localeCompare(b.toLowerCase())
  })

  return keys.map(key => ({ name: key, count: countMap[key] }))
}

/**
 * Gets a list of categories and their counts from the "posts" and "writeups" collections.
 */
export async function getCategoryList(): Promise<Category[]> {
  const blogPosts = await getCollection('posts', ({ data }) => {
    return import.meta.env.PROD ? data.draft !== true : true
  })

  const writeups = await getCollection('writeups', ({ data }) => {
    return import.meta.env.PROD ? data.draft !== true : true
  })

  const allPosts = [...blogPosts, ...writeups]

  const count: { [key: string]: number } = {}
  allPosts.map(post => {
    if (!post.data.category) {
      const ucKey = i18n(I18nKey.uncategorized)
      count[ucKey] = count[ucKey] ? count[ucKey] + 1 : 1
      return
    }
    count[post.data.category] = count[post.data.category]
      ? count[post.data.category] + 1
      : 1
  })

  const lst = Object.keys(count).sort((a, b) => {
    return a.toLowerCase().localeCompare(b.toLowerCase())
  })

  const ret: Category[] = []
  for (const c of lst) {
    ret.push({ name: c, count: count[c] })
  }
  return ret
}

// Type definitions
export type Tag = {
  name: string
  count: number
}

export type Category = {
  name: string
  count: number
}

/**
 * Returns all children posts of a given series id within a collection.
 * If `series.order` is provided on children, sorts ascending by it; otherwise falls back to published date.
 */
export async function getSeriesChildren(
  seriesId: string,
  collectionName: 'posts' | 'writeups',
): Promise<{ body: string; data: BlogPostData; slug: string; collection: 'posts' | 'writeups' }[]> {
  const entries = await getSortedEntries(collectionName)
  const children = entries.filter(e => e.data.series && e.data.series.id === seriesId && e.data.series.parent !== true)

  const hasAnyOrder = children.some(c => typeof c.data.series?.order === 'number')
  if (hasAnyOrder) {
    // Sort by explicit order (undefined goes last), then by published date
    return children.sort((a, b) => {
      const ao = a.data.series?.order
      const bo = b.data.series?.order
      if (ao === undefined && bo === undefined) return new Date(a.data.published) > new Date(b.data.published) ? -1 : 1
      if (ao === undefined) return 1
      if (bo === undefined) return -1
      return ao - bo
    })
  }
  // Default sort by published desc
  return children.sort((a, b) => (new Date(a.data.published) > new Date(b.data.published) ? -1 : 1))
}

export async function getSortedWriteups(): Promise<
  { body: string; data: BlogPostData; slug: string; collection: 'posts' | 'writeups' }[]
> {
  const entries = await getSortedEntries('writeups')
  return entries.filter(e => !(e.data.series && e.data.series.parent !== true))
}