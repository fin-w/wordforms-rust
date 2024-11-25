use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::env::{args, current_dir};
use std::fs::File;
use std::io::{self, BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::str;
use substring::Substring;
use unicode_segmentation::UnicodeSegmentation;

const HELP_TEXT: &str = "Usage: wordforms [-s | -p] DICTIONARY.aff DICTIONARY.dic STEM
       wordforms -g DICTIONARY.aff DICTIONARY.dic OUTPUT_FILE
Generate all variations of a word stem STEM in the dictionary file DICTIONARY.dic by
affixing all prefixes and suffixes listed as flags of the stem, based on rules stored
in DICTIONARY.aff, and print the results. If -g is given, generate every variation of
every stem in the dictionary file DICTIONARY.dic by affixing all relevant flags, and
write the results to file OUTPUT_FILE. Note that typically this will generate tens of
thousands of words.

  -s  print only the stem, and any suffixed forms of the stem
  -p  print only the stem, and any prefixed forms of the stem
  -g  generate all words in the entire dictionary and save them to a file";

#[derive(Debug)]
struct EntryToProcess {
    stem: String,
    prefix_flags: HashSet<String>,
    suffix_flags: HashSet<String>,
    flags_affixed: Vec<String>,
    times_prefixed: u8,
    times_suffixed: u8,
}

#[derive(Debug)]
struct AffixData {
    delete: usize,
    regex: Regex,
    add: String,
    prefix_flags: HashSet<String>,
    suffix_flags: HashSet<String>,
}

#[derive(PartialEq)]
enum GenerationBehaviour {
    PrefixesOnly,
    SuffixesOnly,
    PrefixesAndSuffixes,
    AllWordsInDictionary,
}

#[derive(PartialEq, Clone)]
enum HunspellAffixFlagType {
    Utf8,
    Long,
    Number,
}

struct HunspellAffFileData {
    complex_prefixes: bool,
    flag_type: HunspellAffixFlagType,
    prefix_database: HashMap<String, Vec<AffixData>>,
    suffix_database: HashMap<String, Vec<AffixData>>,
}

fn print_help_and_exit(error_text: &str, print_standard_help: bool) {
    if !error_text.is_empty() {
        eprintln!("wordforms: {error_text}");
    }
    if print_standard_help {
        eprintln!("{HELP_TEXT}");
    }
    process::exit(1);
}

// The output is wrapped in a Result to allow matching on errors.
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn separate_flags(
    flags: &str,
    flag_type: &HunspellAffixFlagType,
    prefix_database: &HashMap<String, Vec<AffixData>>,
    suffix_database: &HashMap<String, Vec<AffixData>>,
) -> (HashSet<String>, HashSet<String>, HashSet<String>) {
    let mut separated_flags: HashSet<String> = HashSet::new();
    match *flag_type {
        HunspellAffixFlagType::Number => {
            separated_flags = flags.split(',').map(|s| s.to_string()).collect();
        }
        HunspellAffixFlagType::Long => {
            let individual_graphemes: Vec<&str> =
                UnicodeSegmentation::graphemes(flags, true).collect();
            for grapheme_pair in individual_graphemes.chunks(2) {
                if let [first, second] = grapheme_pair {
                    separated_flags.insert(format!("{}{}", first, second));
                }
            }
        }
        HunspellAffixFlagType::Utf8 => {
            separated_flags = UnicodeSegmentation::graphemes(flags, true)
                .map(|s| s.to_string())
                .collect();
        }
    }
    let prefix_flags: HashSet<String> = separated_flags
        .iter()
        .filter(|&f| prefix_database.contains_key(f))
        .cloned()
        .collect();
    let suffix_flags: HashSet<String> = separated_flags
        .iter()
        .filter(|&f| suffix_database.contains_key(f))
        .cloned()
        .collect();
    (separated_flags, prefix_flags, suffix_flags)
}

fn apply_prefix(
    entry: &EntryToProcess,
    rule_name: String,
    rule: &AffixData,
    all_variations: &mut HashSet<String>,
    to_be_processed_: &mut Vec<EntryToProcess>,
    complex_prefixes: &bool,
) {
    let affixed_stem: String = format!(
        "{}{}",
        rule.add,
        entry
            .stem
            .substring(rule.delete, entry.stem.chars().count())
    );
    all_variations.insert(affixed_stem.clone());
    let mut f_a = entry.flags_affixed.clone();
    f_a.push(rule_name);
    let mut called_prefix_flags: HashSet<String> = HashSet::new();
    let mut called_suffix_flags: HashSet<String> = HashSet::new();
    // Add affixes called by the prefix we just added.
    // If we can add a second prefix (we've prefixed once but times_prefixed == 0 still).
    if *complex_prefixes && entry.times_prefixed == 0 && !rule.prefix_flags.is_empty() {
        called_prefix_flags = rule.prefix_flags.clone();
    }
    // If we can add a suffix / second suffix.
    if ((!*complex_prefixes && entry.times_suffixed < 2)
        || (*complex_prefixes && entry.times_suffixed == 0))
        && !rule.suffix_flags.is_empty()
    {
        called_suffix_flags = rule.suffix_flags.clone();
        called_suffix_flags.extend(entry.suffix_flags.iter().cloned());
        called_suffix_flags.retain(|f| !entry.flags_affixed.contains(f));
    }

    if !called_prefix_flags.is_empty() || !called_suffix_flags.is_empty() {
        to_be_processed_.push(EntryToProcess {
            stem: affixed_stem.clone(),
            prefix_flags: called_prefix_flags,
            suffix_flags: called_suffix_flags,
            flags_affixed: f_a.clone(),
            times_prefixed: entry.times_prefixed + 1_u8,
            times_suffixed: entry.times_suffixed,
        });
    }
}

fn apply_suffix(
    entry: &EntryToProcess,
    rule_name: String,
    rule: &AffixData,
    all_variations: &mut HashSet<String>,
    to_be_processed_: &mut Vec<EntryToProcess>,
    complex_prefixes: &bool,
) {
    let affixed_stem: String = format!(
        "{}{}",
        entry
            .stem
            .substring(0, entry.stem.chars().count() - rule.delete),
        rule.add
    );
    all_variations.insert(affixed_stem.clone());
    let mut f_a = entry.flags_affixed.clone();
    f_a.push(rule_name);
    let mut called_prefix_flags: HashSet<String> = HashSet::new();
    let mut called_suffix_flags: HashSet<String> = HashSet::new();
    // Add affixes called by the suffix we just added.
    // If we can add a second suffix (we've suffixed once but times_suffixed == 0 still).
    if !*complex_prefixes && entry.times_suffixed == 0 && !rule.suffix_flags.is_empty() {
        called_suffix_flags = rule.suffix_flags.clone();
    }
    // If we can add a prefix / second prefix.
    if ((*complex_prefixes && entry.times_prefixed < 2)
        || (!*complex_prefixes && entry.times_prefixed == 0))
        && !rule.prefix_flags.is_empty()
    {
        called_prefix_flags = rule.prefix_flags.clone();
        called_prefix_flags.extend(entry.prefix_flags.iter().cloned());
        called_prefix_flags.retain(|f| !entry.flags_affixed.contains(f));
    }

    if !called_prefix_flags.is_empty() || !called_suffix_flags.is_empty() {
        to_be_processed_.push(EntryToProcess {
            stem: affixed_stem.clone(),
            prefix_flags: called_prefix_flags,
            suffix_flags: called_suffix_flags,
            flags_affixed: f_a.clone(),
            times_prefixed: entry.times_prefixed,
            times_suffixed: entry.times_suffixed + 1_u8,
        });
    }
}

fn apply_sandwich_affix(
    entry: &EntryToProcess,
    prefix_rule: &AffixData,
    suffix_rule: &AffixData,
    all_variations: &mut HashSet<String>,
) {
    let prefixed_stem: String = format!(
        "{}{}",
        prefix_rule.add,
        entry
            .stem
            .substring(prefix_rule.delete, entry.stem.chars().count())
    );
    let affixed_stem: String = format!(
        "{}{}",
        prefixed_stem.substring(0, prefixed_stem.chars().count() - suffix_rule.delete),
        suffix_rule.add
    );
    all_variations.insert(affixed_stem.clone());
}

fn affix_word(
    entry: &EntryToProcess,
    complex_prefixes: &bool,
    to_be_processed_: &mut Vec<EntryToProcess>,
    all_variations: &mut HashSet<String>,
    prefix_database: &HashMap<String, Vec<AffixData>>,
    suffix_database: &HashMap<String, Vec<AffixData>>,
) {
    if ((entry.times_prefixed < 3) && *complex_prefixes)
        || ((entry.times_prefixed < 2) && !*complex_prefixes)
    {
        for p in &entry.prefix_flags {
            for prefix_rule in &prefix_database[p] {
                if prefix_rule.regex.is_match(&entry.stem) {
                    apply_prefix(
                        entry,
                        p.to_string(),
                        prefix_rule,
                        all_variations,
                        to_be_processed_,
                        complex_prefixes,
                    );
                }
            }
        }
    }
    if ((entry.times_suffixed < 3) && !*complex_prefixes)
        || ((entry.times_suffixed < 2) && *complex_prefixes)
    {
        for s in &entry.suffix_flags {
            for suffix_rule in &suffix_database[s] {
                if suffix_rule.regex.is_match(&entry.stem) {
                    apply_suffix(
                        entry,
                        s.to_string(),
                        suffix_rule,
                        all_variations,
                        to_be_processed_,
                        complex_prefixes,
                    );
                }
            }
        }
    }
    // Sandwich affix all adjacent prefixes and suffixes.
    if (!entry.prefix_flags.is_empty() && !entry.suffix_flags.is_empty())
        && (((entry.times_prefixed < 3) && *complex_prefixes)
            || ((entry.times_prefixed < 2) && !*complex_prefixes))
        && ((entry.times_suffixed < 3) && !complex_prefixes.to_owned())
        || ((entry.times_suffixed < 2) && complex_prefixes.to_owned())
    {
        for p in &entry.prefix_flags {
            for prefix_rule in &prefix_database[p] {
                if prefix_rule.regex.is_match(&entry.stem) {
                    for s in &entry.suffix_flags {
                        for suffix_rule in &suffix_database[s] {
                            if suffix_rule.regex.is_match(&entry.stem) {
                                apply_sandwich_affix(
                                    entry,
                                    prefix_rule,
                                    suffix_rule,
                                    all_variations,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn build_affix_data(requested_behaviour: GenerationBehaviour) -> HunspellAffFileData {
    let mut prefix_database: HashMap<String, Vec<AffixData>> = HashMap::new();
    let mut suffix_database: HashMap<String, Vec<AffixData>> = HashMap::new();
    let mut prefix_names: Vec<String> = Vec::new();
    let mut suffix_names: Vec<String> = Vec::new();
    let mut prefix_raw_data: Vec<Vec<String>> = Vec::new();
    let mut suffix_raw_data: Vec<Vec<String>> = Vec::new();
    let mut affix_data = Vec::new();
    let mut complex_prefixes: bool = false;
    let mut flag_type = HunspellAffixFlagType::Utf8;
    if let Ok(lines) = read_lines("/tmp/wordforms.aff") {
        for line in lines.map_while(Result::ok) {
            affix_data.push(line);
        }
    }
    for line in affix_data {
        if !(line.starts_with('#')
            || line.starts_with(' ')
            || line.starts_with('\t')
            || line.is_empty())
        {
            let iter: str::SplitWhitespace<'_> = line.split_whitespace();
            let vals: Vec<&str> = iter.collect();
            // Complex prefixes shouldn't have anything after it that's not a comment.
            if vals[0] == "COMPLEXPREFIXES" {
                complex_prefixes = true;
            } else if vals[0] == "FLAG" {
                match vals[1] {
                    "UTF-8" => flag_type = HunspellAffixFlagType::Utf8,
                    "long" => flag_type = HunspellAffixFlagType::Long,
                    "num" => flag_type = HunspellAffixFlagType::Number,
                    _ => print_help_and_exit(
                        "Failed to read dictionary flag type (found flag type {vals[1]}).",
                        false,
                    ),
                }
            } else if vals[0] == "PFX"
                && vals.len() > 4
                && requested_behaviour != GenerationBehaviour::SuffixesOnly
            {
                prefix_names.push(vals[1].to_string());
                prefix_raw_data.push(vec![
                    vals[1].to_owned(),
                    vals[2].to_owned(),
                    vals[3].to_owned(),
                    vals[4].to_owned(),
                ]);
            } else if vals[0] == "SFX"
                && vals.len() > 4
                && requested_behaviour != GenerationBehaviour::PrefixesOnly
            {
                suffix_names.push(vals[1].to_string());
                suffix_raw_data.push(vec![
                    vals[1].to_owned(),
                    vals[2].to_owned(),
                    vals[3].to_owned(),
                    vals[4].to_owned(),
                ]);
            }
        }
    }
    // Now that we know the names of the affixes, separate
    // the prefixes / suffixes called by each flag.
    for vals in prefix_raw_data {
        let iter = vals[2].split('/');
        let a_f: Vec<&str> = iter.collect();
        let p_d: (HashSet<String>, HashSet<String>, HashSet<String>) = if a_f.len() > 1 {
            separate_flags(a_f[1], &flag_type, &prefix_database, &suffix_database)
        } else {
            (HashSet::new(), HashSet::new(), HashSet::new())
        };
        let (flags, _prefix_flags, _suffix_flags) = p_d;
        match Regex::new(format!("^{}", vals[3]).as_str()) {
            Ok(regex) => prefix_database
                .entry(vals[0].to_string())
                .or_default()
                .push(AffixData {
                    delete: if &vals[1].to_string() == "0" {
                        0
                    } else {
                        vals[1].to_string().chars().count()
                    },
                    regex,
                    add: if a_f[0] == "0" {
                        String::new()
                    } else {
                        a_f[0].to_string()
                    },
                    prefix_flags: flags
                        .clone()
                        .into_iter()
                        .filter(|f| prefix_names.contains(f))
                        .collect(),
                    suffix_flags: flags
                        .clone()
                        .into_iter()
                        .filter(|f| suffix_names.contains(f))
                        .collect(),
                }),
            Err(e) => print_help_and_exit(e.to_string().as_str(), false),
        }
    }
    for vals in suffix_raw_data {
        let iter = vals[2].split('/');
        let a_f: Vec<&str> = iter.collect();
        let p_d: (HashSet<String>, HashSet<String>, HashSet<String>) = if a_f.len() > 1 {
            separate_flags(a_f[1], &flag_type, &prefix_database, &suffix_database)
        } else {
            (HashSet::new(), HashSet::new(), HashSet::new())
        };
        let (flags, _prefix_flags, _suffix_flags) = p_d;
        match Regex::new(format!("{}$", vals[3]).as_str()) {
            Ok(regex) => suffix_database
                .entry(vals[0].to_string())
                .or_default()
                .push(AffixData {
                    delete: if &vals[1].to_string() == "0" {
                        0
                    } else {
                        vals[1].to_string().chars().count()
                    },
                    regex,
                    add: if a_f[0] == "0" {
                        String::new()
                    } else {
                        a_f[0].to_string()
                    },
                    prefix_flags: flags
                        .clone()
                        .into_iter()
                        .filter(|f| prefix_names.contains(f))
                        .collect(),
                    suffix_flags: flags
                        .clone()
                        .into_iter()
                        .filter(|f| suffix_names.contains(f))
                        .collect(),
                }),
            Err(e) => print_help_and_exit(e.to_string().as_str(), false),
        }
    }
    HunspellAffFileData {
        complex_prefixes,
        flag_type,
        prefix_database,
        suffix_database,
    }
}

fn generate(stems: Vec<String>, requested_behaviour: GenerationBehaviour) -> HashSet<String> {
    let mut all_variations: HashSet<String> = HashSet::with_capacity(1500000);
    let mut to_be_processed: Vec<EntryToProcess> = Vec::new();

    let affix_data: HunspellAffFileData = build_affix_data(requested_behaviour);

    for e in stems {
        let entry_and_flags: Vec<&str> = e.split('/').collect();
        all_variations.insert(entry_and_flags[0].to_string());
        if entry_and_flags.len() > 1 {
            let (_flags, prefix_flags, suffix_flags) = separate_flags(
                entry_and_flags[1],
                &affix_data.flag_type,
                &affix_data.prefix_database,
                &affix_data.suffix_database,
            );
            let a_f = Vec::new();
            to_be_processed.push(EntryToProcess {
                stem: entry_and_flags[0].to_string(),
                prefix_flags,
                suffix_flags,
                flags_affixed: a_f,
                times_prefixed: 0,
                times_suffixed: 0,
            });
            let mut process: bool = true;
            while process {
                let mut to_be_processed_: Vec<EntryToProcess> = Vec::new();
                for entry in &to_be_processed {
                    if (entry.times_prefixed + entry.times_suffixed) < 4 {
                        affix_word(
                            entry,
                            &affix_data.complex_prefixes,
                            &mut to_be_processed_,
                            &mut all_variations,
                            &affix_data.prefix_database,
                            &affix_data.suffix_database,
                        );
                    }
                }
                process = !to_be_processed_.is_empty();
                to_be_processed = to_be_processed_;
            }
        }
    }
    all_variations
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut requested_behaviour = GenerationBehaviour::PrefixesAndSuffixes;
    let args: Vec<String> = args().collect();
    let _ = std::fs::remove_file("/tmp/wordforms.aff");
    let _ = std::fs::remove_file("/tmp/wordforms.dic");
    let pwd = current_dir()?;
    let mut affix_file_path = PathBuf::from("");
    let mut dictionary_file_path = PathBuf::from("");
    let mut output_file_or_stem_from_args: &str = "";
    let mut stems = Vec::new();
    match args.len() {
        4 => {
            // Find matching stems.
            affix_file_path = pwd.join(args[1].as_str());
            dictionary_file_path = pwd.join(args[2].as_str());
            output_file_or_stem_from_args = &args[3];
        }
        5 => {
            match args[1].as_str() {
                "-s" => requested_behaviour = GenerationBehaviour::SuffixesOnly,
                "-p" => requested_behaviour = GenerationBehaviour::PrefixesOnly,
                "-g" => requested_behaviour = GenerationBehaviour::AllWordsInDictionary,
                _ => print_help_and_exit("", true),
            }
            affix_file_path = pwd.join(&args[2]);
            dictionary_file_path = pwd.join(&args[3]);
            output_file_or_stem_from_args = &args[4];
        }
        _ => {
            print_help_and_exit("", true);
        }
    }
    if !affix_file_path.is_file() {
        print_help_and_exit(
            format!(
                "Could not find the specified .aff file {}",
                affix_file_path.to_string_lossy()
            )
            .as_str(),
            true,
        );
    }
    if !dictionary_file_path.is_file() {
        print_help_and_exit(
            format!(
                "Could not find the specified .dic file {}",
                dictionary_file_path.to_string_lossy()
            )
            .as_str(),
            true,
        );
    }
    if std::os::unix::fs::symlink(&affix_file_path, "/tmp/wordforms.aff").is_err() {
        print_help_and_exit(
            format!(
                "Failed to create symlink between file {} and symlink /tmp/wordforms.aff",
                affix_file_path.to_string_lossy()
            )
            .as_str(),
            true,
        );
    }
    match requested_behaviour {
        GenerationBehaviour::AllWordsInDictionary => {
            if std::os::unix::fs::symlink(&dictionary_file_path, "/tmp/wordforms.dic").is_err() {
                print_help_and_exit(
                    format!(
                        "Failed to create symlink between file {} and symlink /tmp/wordforms.dic",
                        affix_file_path.to_string_lossy()
                    )
                    .as_str(),
                    true,
                );
            }
            match read_lines("/tmp/wordforms.dic") {
                Ok(lines) => {
                    for line in lines.map_while(Result::ok).skip(1) {
                        stems.push(
                            line.split('\t')
                                .next()
                                .unwrap()
                                .split(" #")
                                .next()
                                .unwrap()
                                .to_string(),
                        );
                    }
                }
                Err(_) => print_help_and_exit(
                    format!(
                        "Failed to read symlink /tmp/wordforms.dic which links to file {}",
                        dictionary_file_path.to_string_lossy()
                    )
                    .as_str(),
                    true,
                ),
            }

            if let Ok(file) = File::create("/tmp/wordforms.output") {
                let mut output_file = BufWriter::new(file);
                let results = generate(stems, requested_behaviour);
                for r in results {
                    let _ = output_file.write(r.as_bytes());
                    let _ = output_file.write("\n".as_bytes());
                }
                output_file.flush()?;
                let hunspell_output = Command::new("sh")
                    .arg("-c")
                    .arg("hunspell -d /tmp/wordforms -G -l /tmp/wordforms.output")
                    .output()
                    .expect("wordforms: Hunspell failed to spellcheck generated word list.");
                if let Ok(file) = File::create(output_file_or_stem_from_args) {
                    output_file = BufWriter::new(file);
                    let _ = output_file.write(hunspell_output.stdout.as_slice());
                    output_file.flush()?;
                    Command::new("/bin/bash")
                        .arg("-c")
                        .arg(
                            format!(
                                "WC_ALL=C sort -u -o {} {}",
                                output_file_or_stem_from_args, output_file_or_stem_from_args
                            )
                            .as_str(),
                        )
                        .status()
                        .expect("Something went wrong while running sort on the generated words");
                } else {
                    print_help_and_exit(
                        format!(
                            "Failed to write spellchecked results to file {}",
                            output_file_or_stem_from_args
                        )
                        .as_str(),
                        true,
                    )
                }
            } else {
                print_help_and_exit(
                    format!(
                        "Failed to open file {} to write into",
                        dictionary_file_path.to_string_lossy()
                    )
                    .as_str(),
                    true,
                );
            }
        }
        _ => {
            // -s or -p, so find matching stems like in `match args.len() { 4 => { } }` above.
            let stem_from_args_with_slash: String = format!("{output_file_or_stem_from_args}/");
            let mut stems_paste = String::new();
            if let Ok(lines) = read_lines(&dictionary_file_path) {
                for line in lines.map_while(Result::ok) {
                    if line.eq(&output_file_or_stem_from_args)
                        || line.starts_with(&stem_from_args_with_slash)
                    {
                        let formatted_line = line
                            .split('\t')
                            .next()
                            .unwrap()
                            .split(" #")
                            .next()
                            .unwrap()
                            .to_string();
                        stems_paste = format!("{stems_paste}\n{}", &formatted_line);
                        stems.push(formatted_line);
                    }
                }
            }
            let stems_len = stems.len();
            // If no matches, exit.
            if stems_len == 0 {
                process::exit(1);
            }
            if let Ok(file) = File::create("/tmp/wordforms.dic") {
                let mut tmp_dic = BufWriter::new(file);
                stems_paste = format!("{stems_len}{stems_paste}\n");
                let _ = tmp_dic.write(stems_paste.as_bytes());
                tmp_dic.flush()?;
                let results = generate(stems, requested_behaviour);
                for r in results {
                    println!("{r}");
                }
            } else {
                print_help_and_exit(
                    "Failed to create file /tmp/wordforms.dic to write into",
                    true,
                );
            }
        }
    }
    Ok(())
}
